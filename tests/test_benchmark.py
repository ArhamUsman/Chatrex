from __future__ import annotations

import copy
import statistics
from dataclasses import replace

import pytest

from chatrex import benchmark


def settings_for(tmp_path, **changes):
    settings = benchmark.Settings(
        environment="local",
        modes=("plaintext", "tls", "e2e"),
        sizes=(64,),
        rtts=(0,),
        messages=2,
        runs=2,
        seed=17,
        output=tmp_path / "results",
        resume=False,
        capture=False,
        capture_reason="loopback test",
    )
    return replace(settings, **changes)


def test_cli_defaults_and_dependent_rtt_defaults(tmp_path, monkeypatch):
    parser = benchmark.build_parser()
    local = benchmark._resolve_settings(parser.parse_args([]))
    assert local.environment == "local"
    assert local.modes == benchmark.DEFAULT_MODES
    assert local.sizes == benchmark.DEFAULT_SIZES
    assert local.rtts == (0,)
    assert local.messages == 1000
    assert local.runs == 3
    assert local.seed == 0
    assert local.capture is False
    assert "loopback" in local.capture_reason

    monkeypatch.setattr(benchmark.os, "geteuid", lambda: 0)
    lab = benchmark._resolve_settings(
        parser.parse_args(["--environment", "lab", "--no-capture"])
    )
    assert lab.rtts == (20, 100, 200)
    repetitions = parser.parse_args(["--repetitions", "4"])
    assert repetitions.runs == 4


def test_cli_rejects_delayed_localhost_and_bad_lists(tmp_path):
    parser = benchmark.build_parser()
    with pytest.raises(benchmark.BenchmarkError, match="only --rtts 0"):
        benchmark._resolve_settings(parser.parse_args(["--rtts", "20"]))
    with pytest.raises(benchmark.BenchmarkError, match="duplicate"):
        benchmark._resolve_settings(parser.parse_args(["--modes", "tls,tls"]))
    with pytest.raises(benchmark.BenchmarkError, match="unsupported"):
        benchmark._resolve_settings(parser.parse_args(["--modes", "tls,unknown"]))
    with pytest.raises(benchmark.BenchmarkError, match="positive"):
        benchmark._resolve_settings(parser.parse_args(["--messages", "0"]))


def test_payloads_are_seeded_unique_and_run_scoped():
    first = benchmark.generate_payloads(42, 64, 20, "run-a")
    assert first == benchmark.generate_payloads(42, 64, 20, "run-a")
    assert first != benchmark.generate_payloads(43, 64, 20, "run-a")
    assert first != benchmark.generate_payloads(42, 64, 20, "run-b")
    assert len(first) == len(set(first)) == 20
    assert all(len(payload) == 64 for payload in first)

    small = benchmark.generate_payloads(1, 1, 256, "tiny")
    assert len(set(small)) == 256
    with pytest.raises(ValueError, match="too small"):
        benchmark.generate_payloads(1, 1, 257, "tiny")


def test_latency_statistics_include_sample_sd_and_percentiles():
    result = benchmark.latency_stats([1.0, 2.0, 3.0, 4.0])
    assert result["count"] == 4
    assert result["mean_ms"] == 2.5
    assert result["sample_sd_ms"] == statistics.stdev([1.0, 2.0, 3.0, 4.0])
    assert result["median_ms"] == 2.5
    assert result["p95_ms"] == pytest.approx(3.85)
    assert result["p99_ms"] == pytest.approx(3.97)
    assert result["min_ms"] == 1.0
    assert result["max_ms"] == 4.0
    assert benchmark.latency_stats([2.0])["sample_sd_ms"] is None


def make_valid_run(tmp_path, settings, run_number=1):
    condition = benchmark.Condition(0, "plaintext", 64)
    run_dir = settings.output / condition.name / f"run-{run_number}"
    run_dir.mkdir(parents=True)
    run_id = benchmark._run_id(condition, run_number)
    rows = []
    for sequence in range(settings.messages):
        send = 1_000_000_000 + sequence * 2_000_000
        recv = send + 1_000_000 + sequence * 500_000
        rows.append({
            "run_id": run_id,
            "seq": sequence,
            "send_monotonic_ns": send,
            "recv_monotonic_ns": recv,
            "latency_ms": (recv - send) / 1e6,
            "echo_ok": True,
        })
    benchmark._write_latencies(run_dir / "latencies.csv", rows)
    benchmark._write_json(run_dir / "sender_setup_done.json", {
        "status": "ready", "run_id": run_id,
    })
    benchmark._write_json(run_dir / "sender_done.json", {
        "status": "success",
        "run_id": run_id,
        "messages": settings.messages,
        "all_echoes_validated": True,
    })
    benchmark._write_json(run_dir / "echo_done.json", {
        "status": "success",
        "run_id": run_id,
        "echoed_messages": settings.messages,
        "same_message_ids": True,
        "payloads_validated": True,
    })
    latencies = [row["latency_ms"] for row in rows]
    document = benchmark._base_run_document(
        settings, condition, run_number, run_dir, measured_rtt=None
    )
    document.update({
        "status": "success",
        "finished_at_utc": benchmark._utc_now(),
        "setup": {
            "total_setup_ms": 10.0 + run_number,
            "setup_rtt_ratio": None,
        },
        "latency": benchmark.latency_stats(latencies),
        "cpu": {
            "client": {
                "setup_seconds": 0.1,
                "message_seconds": 0.2,
                "total_seconds": 0.3,
                "message_ms_per_message": 100.0,
            },
            "relay": {
                "setup_seconds": 0.01,
                "message_seconds": 0.02,
                "total_seconds": 0.03,
                "message_ms_per_message": 10.0,
            },
        },
        "wire_statistics": None,
    })
    benchmark._write_json(run_dir / "run.json", document)
    return condition, document, run_dir


def test_resume_accepts_only_complete_matching_success(tmp_path):
    settings = settings_for(tmp_path)
    condition, document, run_dir = make_valid_run(tmp_path, settings)
    assert benchmark._valid_completed_run(settings, condition, 1) == document

    mismatched = replace(settings, messages=3)
    assert benchmark._valid_completed_run(mismatched, condition, 1) is None

    text = (run_dir / "latencies.csv").read_text()
    (run_dir / "latencies.csv").write_text(text.replace("True", "False", 1))
    assert benchmark._valid_completed_run(settings, condition, 1) is None


def test_resume_manifest_rejects_reduced_smoke_configuration(tmp_path):
    smoke = settings_for(tmp_path)
    condition = benchmark.Condition(0, "plaintext", 64)
    smoke.output.mkdir()
    manifest = benchmark._new_manifest(smoke, [condition])
    benchmark._write_json(smoke.output / "manifest.json", manifest)
    full = replace(smoke, messages=1000, runs=3, resume=True)
    with pytest.raises(benchmark.BenchmarkError, match="reduced smoke"):
        benchmark._load_resume_manifest(full, [condition])


def test_condition_aggregation_uses_sample_sd_and_exposes_incomplete(tmp_path):
    settings = settings_for(tmp_path)
    condition, first, _run_dir = make_valid_run(tmp_path, settings)
    second = copy.deepcopy(first)
    second["run_id"] = benchmark._run_id(condition, 2)
    second["run_number"] = 2
    second["setup"]["total_setup_ms"] = 20.0
    second["latency"]["mean_ms"] = 3.0
    failed = copy.deepcopy(second)
    failed["run_id"] = benchmark._run_id(condition, 3)
    failed["status"] = "failed"

    row = benchmark._summary_row(condition, 3, [first, second, failed])
    assert row["successful_runs"] == 2
    assert row["failed_runs"] == 1
    assert row["complete"] is False
    assert row["setup_ms_mean"] == pytest.approx(15.5)
    assert row["setup_ms_sample_sd"] == pytest.approx(statistics.stdev([11.0, 20.0]))
    assert row["message_latency_ms_sample_sd"] == pytest.approx(
        statistics.stdev([first["latency"]["mean_ms"], 3.0])
    )
    assert row["wire_ratio_mean"] is None
