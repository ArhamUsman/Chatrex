# Project 2 requirements and evidence checklist

This checklist distinguishes **code/document readiness** from **actual submission evidence**. No claim of full completion is intended.

### Status meanings

- **Implemented** — the source, script, or requested document exists and is wired into the project.
- **Smoke-verified** — supported by tests or the genuine reduced local smoke suite; this is not routed/full-matrix proof.
- **Pending privileged lab run** — requires the root-equipped two-router execution and/or evidence that has not yet been produced.

A requirement can therefore be `Implemented` in the first status column and `Pending privileged lab run` in the evidence column. The only current benchmark suite is `results/agent-smoke/`: **5 messages, 64 B, local 0 ms RTT, 1 run per mode, 3 runs total, capture disabled**.

## 1. Functional and security requirements

| Requirement | Implementation and evidence location | Implementation status | Submission evidence status |
|---|---|---|---|
| TCP relay and clients | Threaded relay in `chatrex/relay.py`; shared client in `chatrex/client.py`; root `server.py`/`client.py`; integration tests. | Implemented | Smoke-verified |
| Deterministic length framing | Four-byte unsigned big-endian length + exact-length UTF-8 JSON body in `chatrex/protocol.py`; malformed/partial-frame tests. | Implemented | Smoke-verified |
| Versioned registration, room create/join, roster, send/delivery | `register`, `welcome`, `roster`, `send`, `deliver`, and `error` paths; six-digit rooms and PBKDF2 verifier; CLI/GUI use the shared core. | Implemented | Smoke-verified |
| Plaintext baseline | Separate TCP 8080 listener accepting only `plaintext`; warnings in CLI/GUI/README; smoke `rtt-0ms_plaintext_64B`. | Implemented | Smoke-verified |
| TLS 1.3 with local CA | `gen_certs.sh`; CA/server SANs; TLS 1.3-only contexts and hostname/IP verification; TCP 8443; smoke run records `TLSv1.3`, no session reuse. | Implemented | Smoke-verified |
| Immediate secure handshake / no plaintext upgrade | Relay wraps accepted secure sockets before registration; secure listener accepts only TLS/E2E. | Implemented | Smoke-verified |
| TLS + E2E using X25519 NaCl Box | Persistent X25519 identities; fresh 24-byte nonces; per-recipient authenticated Box; inner metadata validation in `chatrex/security.py`; smoke E2E run. | Implemented | Smoke-verified |
| Full fingerprints and explicit peer verification | Domain-separated SHA-256 fingerprint binds username/key; room-scoped trust store; CLI `/fingerprint`, `/peers`, `/verify`; GUI equivalent; unverified sends blocked. | Implemented | Smoke-verified |
| Relay cannot decrypt verified E2E content | Relay forwards nonce/ciphertext and has no endpoint private-key/Box operation; attacker-visibility analysis in the technical report. | Implemented | Pending privileged lab run |
| Distinct trust boundaries documented | [ARCHITECTURE.md](ARCHITECTURE.md), [architecture.svg](architecture.svg), and report security table distinguish network, relay, CA/TLS, and E2E endpoints. | Implemented | Implemented |
| NiceGUI client on port 8081 | `main.py`; relay host configurable; default UI bind `127.0.0.1:8081`; no automatic relay startup. | Implemented | Implemented |
| Secure local state handling | Atomic 0600 identity/trust writes; password verifier stored rather than plaintext room password; `.gitignore` excludes `user_data/` and secrets. | Implemented | Smoke-verified |

**Evidence still needed for this section:** routed PCAPNG/screenshots showing plaintext readability, TLS 1.3 negotiation/opacity, keylog-assisted TLS outer decoding, E2E ciphertext at the relay, and genuine full-fingerprint verification. Local functional success does not supply those visual artifacts.

## 2. Network topology requirements

| Requirement | Implementation and evidence location | Implementation status | Submission evidence status |
|---|---|---|---|
| Two routers and three subnets | `setup_topology.sh` creates `client`, `r1`, `r2`, `server`; subnets 10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24; static routes and IPv4 forwarding. | Implemented | Pending privileged lab run |
| Correct endpoint addressing | Client `10.0.1.10`; relay `10.0.3.10`; router interfaces 10.0.1.1, 10.0.2.1, 10.0.2.2, 10.0.3.1; table and SVG document every interface. | Implemented | Pending privileged lab run |
| Relay ports in routed lab | Plaintext 8080 and TLS/E2E 8443 on `10.0.3.10`; client selects port by mode. | Implemented | Pending privileged lab run |
| No localhost in routed measurements | Benchmark workers use `10.0.3.10`; echo runs separately in server namespace; README prohibits localhost for lab clients. | Implemented | Pending privileged lab run |
| Configurable RTT/loss/jitter | `setup_topology.sh [RTT_MS] [LOSS_PERCENT] [JITTER_MS]`; input validation and qdisc verification. | Implemented | Pending privileged lab run |
| Delay applied in both directions | `RTT/2` on R1 `veth-r1-b` request egress and R2 `veth-r2-b` response egress; benchmark replaces both per RTT block. | Implemented | Pending privileged lab run |
| Connectivity and route validation | `validate_topology.sh` saves addresses/routes, route-get, bidirectional ping/traceroute, qdiscs, measured average RTT, tolerance, and PASS/FAIL summary. | Implemented | Pending privileged lab run |
| Common architecture diagram | [ARCHITECTURE.md](ARCHITECTURE.md) has the protocol/address tables and Mermaid; [architecture.svg](architecture.svg) is the standalone professional figure. | Implemented | Implemented |

**Evidence still needed:** actual `ip addr/route`, qdisc, bidirectional ping and traceroute artifacts for all required RTT blocks, plus annotated topology screenshots matching the common diagram.

## 3. Full benchmark matrix requirements

| Requirement | Implementation and evidence location | Implementation status | Submission evidence status |
|---|---|---|---|
| 1000 messages per run | `PROJECT_MESSAGES = 1000`; sender/echo completion checks and exactly 1000 latency rows required for a valid full run. | Implemented | Pending privileged lab run |
| Payloads 64, 1024, and 16384 B | `DEFAULT_SIZES`; deterministic unique seeded payload generation and exact-byte echo validation. | Implemented | Pending privileged lab run |
| All three modes at every size/RTT | Defaults iterate RTT → mode → size with no reduced-mode substitution. | Implemented | Pending privileged lab run |
| Added RTTs 20, 100, and 200 ms | `DEFAULT_LAB_RTTS`; per-block netem and topology validation. | Implemented | Pending privileged lab run |
| Three independent runs per condition | `PROJECT_RUNS = 3`; fresh relay/clients per run and no TLS session reuse. | Implemented | Pending privileged lab run |
| Complete 81-run / 81,000-message evaluation | Default 3 × 3 × 3 × 3 matrix; manifest completion counters and configuration signature; resume rejects mismatched/reduced configurations. | Implemented | Pending privileged lab run |
| Reduced runs labeled as smoke | Manifest records message/run reductions; local capture disabled; README/report label existing `agent-smoke` as non-final. | Implemented | Smoke-verified |
| Runtime expectation documented | README/report calculate ~144-minute network-delay lower bound for sequential full matrix, excluding setup/processing overhead. | Implemented | Implemented |

### Current execution ledger

| Evidence item | Current state |
|---|---|
| Automated tests | **123 passed** via `.venv/bin/python -m pytest -q` (verified without cache/bytecode artifacts). |
| Local smoke | **3 / 3 smoke runs successful**; 15 sender messages total; all echoes validated. This is complete only for the reduced manifest. |
| Full routed matrix | **PENDING — 0 / 81 full runs available.** |
| Full routed sender messages | **PENDING — 0 / 81,000 full-evaluation messages available.** |
| Validated 20/100/200 ms routed blocks | **PENDING.** |
| New routed PCAPNG captures | **PENDING.** Old root-level captures are legacy and excluded. |
| Annotated routed screenshots | **PENDING.** No screenshot files are claimed or included. |

## 4. Measurement and statistical requirements

| Requirement | Implementation and evidence location | Implementation status | Submission evidence status |
|---|---|---|---|
| Connection setup time in ms | Sender setup phases and overall setup in `run.json`; aggregate `setup_ms_mean`/`sample_sd` in `summary.csv`; actual smoke values reported. | Implemented | Smoke-verified |
| Setup compared with network RTT | `setup_rtt_ratio` per nonzero-RTT run; RTT-specific output blocks and measured ping values; report table/plot plan. | Implemented | Pending privileged lab run |
| Message round-trip latency | Monotonic send/validated-echo receive timestamps; per-message `latencies.csv`; per-run mean, sample SD, median, p95/p99, min/max. | Implemented | Smoke-verified |
| Wire bytes / payload bytes | Routed capture and `wire_statistics`; ratio divides both frame-byte directions by `2 × messages × payload size`; numerator/denominator documented. | Implemented | Pending privileged lab run |
| PCAPNG output | Automatic per-run tcpdump on `r1/veth-r1-b`; tested standard-library PCAP→PCAPNG converter; `capture.pcapng` linked in `run.json`. | Implemented | Pending privileged lab run |
| Client CPU | Sender user+system setup/message/total CPU seconds and message CPU ms/message; echo CPU also retained in run JSON. | Implemented | Smoke-verified |
| Server CPU | Exact relay PID user+system CPU from `/proc`; setup/message/total seconds and CPU ms/message. | Implemented | Smoke-verified |
| Mean and spread | `summary.csv` emits mean and sample SD across successful run-level values; per-run latency spread retained; missing spread/capture remains null, not zero. | Implemented | Pending privileged lab run |
| Validated message integrity | Echo checks exact ID/bytes; sender checks returned ID/bytes; orchestration validates counts and artifacts before success. | Implemented | Smoke-verified |
| Raw and aggregate output schema | `manifest.json`, `runs.csv`, `summary.csv`, per-run JSON/CSV/logs/topology/captures documented in README and report. | Implemented | Smoke-verified |

**Evidence still needed:** populate every one of the 27 full conditions with three-run mean ± sample SD, setup/RTT analysis, within-run latency spread/percentiles, client/relay CPU, and capture-backed wire ratios. Smoke CPU is too coarse and too short for performance rankings.

## 5. Capture, screenshot, and report requirements

| Requirement | Implementation and evidence location | Implementation status | Submission evidence status |
|---|---|---|---|
| Routed PCAPNG evidence for the modes/conditions | Benchmark supports per-run capture; [EVIDENCE_GUIDE.md](EVIDENCE_GUIDE.md) gives automatic/manual tcpdump commands, paths, conversion, filters, hashes, and validation. | Implemented | Pending privileged lab run |
| Annotated plaintext screenshot | Guide specifies port 8080, framing, JSON registration/send/deliver, Base64 payload, frame/stream annotation. | Implemented | Pending privileged lab run |
| Annotated TLS 1.3 screenshots | Guide requires handshake/version/certificate, no-keylog encrypted records, and separately labeled keylog-assisted outer decoding. | Implemented | Pending privileged lab run |
| Annotated TLS + E2E screenshots | Guide requires no-keylog view, keylog-assisted nonce/ciphertext view, endpoint content correlation, and explicit fingerprint verification. | Implemented | Pending privileged lab run |
| TLS key-log procedure and secrecy | `server.py`/`client.py` options, `SSLKEYLOGFILE` support, benchmark key logs, Wireshark/tshark instructions, and publication exclusions. | Implemented | Pending privileged lab run |
| `tshark` inspection examples | Metadata, directional packet fields, conversations, anomalies, handshake fields, TCP follow, and keylog-assisted verbose decode commands in the guide. | Implemented | Pending privileged lab run |
| Traceroute evidence | Validation script and guide require both directions with expected R1/R2 hops and actual text output. | Implemented | Pending privileged lab run |
| 6–10-page-ready technical report | [TECHNICAL_REPORT.md](TECHNICAL_REPORT.md) contains abstract, objectives, design, protocol, security, methodology, full 27-condition result grid, smoke table, limitations, and conclusion. | Implemented | Pending privileged lab run |
| Full results, plots, and final discussion | Report cells/figures are marked `PENDING`; `plot_results.py` consumes the current `summary.csv` and produces smoke plots without treating missing wire metrics as zero. | Implemented | Pending privileged lab run |
| Polished README / reproducible quickstart | [../README.md](../README.md) includes venv/install, certificates, CLI `/peers`/`/verify`, GUI, exact routed commands, full/smoke benchmarks, plotting, tests, schema, and security. | Implemented | Implemented |
| Separate AI disclosure | [AI_USE.md](AI_USE.md) describes assistance, actual verification, limitations, and evidence boundaries; README/report reference it. | Implemented | Implemented |
| Requirements checklist | This document maps every supplied Project 2 requirement to implementation and evidence with candid statuses. | Implemented | Implemented |

The report's Markdown structure is ready, but its final routed-results section and evidence-based conclusions are not submission-complete. “6–10-page-ready” is a formatting target; final pagination must be checked after inserting real figures and metrics.

## 6. Packaging, safety, and legacy-artifact controls

| Requirement | Implementation and evidence location | Implementation status | Submission evidence status |
|---|---|---|---|
| Python dependencies with reasonable minimums | `requirements.txt`: PyNaCl, NiceGUI, Matplotlib, pytest; no fabricated hashes. | Implemented | Implemented |
| Virtual environment / generated-file exclusion | `.gitignore` excludes `.venv`, caches, `user_data`, results (with optional `.gitkeep`), keys, key logs, captures, legacy exports, and plots. | Implemented | Implemented |
| Legacy root keys/captures not published | README, report, guide, and AI disclosure explicitly exclude old root `ca.key`, `server.key`, `sslkeylog.txt`, `wire_*.pcap`, and `wire_results.txt`. | Implemented | Implemented |
| No fabricated evidence or identities | Full metrics/traces/screenshots are `PENDING`; no team names are supplied; smoke values cite actual files. | Implemented | Implemented |

## 7. Remaining submission gate

The following must be completed before claiming Project 2 is fully demonstrated:

- [ ] On a root-equipped evidence machine, generate/use disposable lab certificates, create the topology, and run the full command with capture required.
- [ ] Verify all three RTT blocks, both traceroute directions, 27 conditions, 81 successful runs, and 1000 valid messages per run.
- [ ] Inspect PCAPNG/capture logs and calculate all wire ratios; investigate losses, retransmissions, and missing runs rather than deleting them.
- [ ] Collect every required annotated screenshot and the full-fingerprint verification evidence according to EVIDENCE_GUIDE.
- [ ] Generate new plots with a documented input path; do not use legacy root text/captures as substitutes.
- [ ] Replace every relevant `PENDING` in the report/checklist with sourced mean ± spread and update abstract/discussion/conclusion consistently.
- [ ] Confirm final 6–10-page formatting after figures are inserted.
- [ ] Review the final archive for private keys, TLS key logs, identity/trust state, credentials, legacy captures, and unsupported claims.
