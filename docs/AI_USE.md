# AI-use disclosure

## Disclosure statement

AI-based coding assistance was used during preparation of ChatreX for software-design reasoning, implementation/test review, debugging support, and documentation. A final documentation and packaging pass used an OpenCode AI coding agent to inspect the supplied project and prepare the README, dependency/ignore rules, architecture documents and SVG, technical report, evidence procedure, requirements checklist, and this disclosure.

Exact model versions, private prompts, and any earlier interaction history that was not reliably recorded are not invented here. No team member names or individual contributions are inferred.

## How assistance was used

| Area | AI-assisted activity | Verification / boundary |
|---|---|---|
| Protocol and security | Reviewed framing, TLS termination, E2E identity/trust behavior, and threat-boundary explanations. | Statements were checked against `chatrex/protocol.py`, `chatrex/security.py`, `chatrex/client.py`, and `chatrex/relay.py`. Design review does not replace a security audit. |
| Topology and benchmark | Reviewed namespace addressing, bidirectional netem, echo methodology, metric definitions, output schemas, and capture workflow. | Commands and defaults were checked against the actual scripts and `chatrex/benchmark.py`. No privileged routed run was available to the assistant. |
| Tests | Checked the test invocation and current functional result. | `.venv/bin/python -m pytest -q -p no:cacheprovider` was executed with bytecode writing disabled; **123 tests passed**. Automated tests do not establish routed-lab completion. |
| Existing measurements | Summarized the genuine local smoke suite. | Values were read from `results/agent-smoke/manifest.json`, `summary.csv`, `runs.csv`, and per-run JSON. They are explicitly labeled 5-message, 64-byte, 0 ms RTT, one-run-per-mode smoke data. |
| Documentation and figure | Drafted usage, architecture, report structure, evidence instructions, requirement mapping, and `docs/architecture.svg`. | Full routed results and evidence are marked `PENDING`. The SVG is a design diagram, not a screenshot of a running topology. |

## Evidence and academic-integrity boundaries

- No benchmark value, packet capture, traceroute, screenshot, team identity, or privileged execution was generated or fabricated by the assistant.
- The existing root-level legacy keys/captures/text results were not promoted into current evidence.
- AI-generated explanations and analysis plans are not experimental observations. Full routed performance claims remain pending actual execution and artifact review.
- TLS key logs, private keys, E2E identities, trust stores, credentials, and other secrets must not be sent to AI services or included in publication archives.
- The submitting author(s) remain responsible for reviewing code and documentation, running the privileged lab, checking every final metric/capture, and supplementing this disclosure if other tools or assistance were used.

## Current unresolved work

The assistant did not claim completion of the 81-run routed evaluation, new routed PCAPNG files, annotated screenshots, or full-lab plots. Those items require root-equipped execution and human review as described in [EVIDENCE_GUIDE.md](EVIDENCE_GUIDE.md) and [REQUIREMENTS_CHECKLIST.md](REQUIREMENTS_CHECKLIST.md).
