# ChatreX: secure multi-mode messaging over a routed TCP laboratory

## Project 2 technical report

**Document state:** implementation complete; local smoke evidence available; full routed evaluation and submission captures/screenshots **PENDING**.  
**Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md) and [architecture.svg](architecture.svg).  
**AI disclosure:** [AI_USE.md](AI_USE.md).  
**Evidence procedure:** [EVIDENCE_GUIDE.md](EVIDENCE_GUIDE.md).  
**Requirement mapping:** [REQUIREMENTS_CHECKLIST.md](REQUIREMENTS_CHECKLIST.md).

> This report is structured for a 6–10 page submission once the pending result cells, figures, captions, and final discussion are populated. `PENDING` means that no qualifying privileged routed measurement exists in the supplied artifacts. It does not mean zero, not applicable, or an estimated result.

---

## Abstract

ChatreX is a room-based TCP messaging system designed to compare plaintext transport, certificate-authenticated TLS 1.3, and TLS 1.3 combined with explicitly verified end-to-end encryption. The implementation uses four-byte length-prefixed JSON frames, a threaded relay with separate plaintext and secure listeners, persistent X25519 client identities, authenticated NaCl Boxes with fresh nonces, and room-scoped SHA-256 fingerprint pins. A Linux network-namespace laboratory places a client and relay on different subnets connected by two forwarding routers. Symmetric netem delay on the inter-router link provides controlled round-trip times while preserving a realistic routed path.

The evaluation design covers 64, 1024, and 16384-byte payloads; 20, 100, and 200 ms added RTT; all three security modes; 1000 sequential request/echo exchanges per run; and three repetitions per condition. The resulting 81-run matrix records setup time and its relationship to RTT, application message latency and spread, frame-byte/payload overhead, sender and relay CPU consumption, PCAPNG evidence, and software/configuration metadata. Fresh protocol peers and validated echo payloads reduce the risk of measuring a broken or unintended data path.

At the time of this report, the implementation passes **122 automated tests**. A genuine local smoke suite completed three runs—one per mode—with five 64-byte messages at 0 ms RTT. Its measurements are reported separately as smoke data only. The required privileged routed suite and new routed packet captures have not been executed in this environment, so no full-matrix performance or security-visibility conclusion is claimed. The principal remaining work is experimental: execute and validate the full matrix, inspect the captures with and without test-only TLS key logs, add annotated evidence, and replace the pending analysis with observed results.

**Keywords:** TCP, TLS 1.3, X25519, NaCl Box, end-to-end encryption, network namespaces, netem, latency, PCAPNG.

## 1. Introduction and objectives

Plaintext networking provides a useful measurement baseline but exposes credentials and content. Transport encryption protects a network path while still trusting the relay that terminates the secure channel. End-to-end encryption changes that trust relationship: the relay can route messages without being able to read their contents, provided endpoint identities are authenticated independently. These are materially different security guarantees, and they also have different setup, processing, and wire-format costs.

The project objectives are to:

1. implement a TCP relay and clients using deterministic length framing rather than assumptions about TCP read boundaries;
2. support an intentionally insecure plaintext baseline and a local-CA-authenticated TLS 1.3 mode;
3. add per-recipient X25519/NaCl Box E2E encryption over TLS, with explicit fingerprint verification rather than trust-on-first-use;
4. construct a reproducible two-router, three-subnet topology with configurable delay, loss, and jitter;
5. measure setup, message latency, wire overhead, and client/server CPU with means and appropriate spread statistics over three runs; and
6. preserve inspectable PCAPNG, topology, screenshot, and machine-readable result evidence without presenting reduced smoke tests as the full evaluation.

The evaluation asks three questions, to be answered only after the routed run:

- **RQ1 — setup:** how do TCP, TLS registration, and E2E verification costs change with network RTT?
- **RQ2 — steady-state cost:** how do mode and payload size affect application round-trip latency, CPU use, and frame-byte/payload ratio?
- **RQ3 — visibility:** what can a passive network observer and a relay operator learn in each mode, and what evidence demonstrates that distinction?

## 2. System design

### 2.1 Components

| Component | Implementation | Responsibility |
|---|---|---|
| Relay | `server.py`, `chatrex/relay.py` | Two TCP listeners, immediate TLS on the secure listener, room creation/authentication, rosters, direct/broadcast forwarding, and opaque E2E forwarding. |
| Shared client core | `chatrex/client.py` | TCP/TLS setup, registration, peer state, explicit trust checks, payload send/receive, echo waits, and setup timing. |
| Protocol | `chatrex/protocol.py` | Four-byte framing, compact versioned JSON, strict UTF-8/Base64 validation, and identifier/size limits. |
| Security | `chatrex/security.py`, `gen_certs.sh` | TLS 1.3 contexts, local CA/certificate generation, X25519 identities, NaCl Box sealing/opening, fingerprints, and persistent trust. |
| Interfaces | `client.py`, `main.py` | Interactive CLI and NiceGUI dashboard; both expose fingerprints and require explicit E2E verification. |
| Laboratory | `setup_topology.sh`, `validate_topology.sh`, `teardown_topology.sh` | Namespace/veth construction, static routing, forwarding, symmetric netem, and saved bidirectional validation evidence. |
| Measurement | `benchmark.py`, `chatrex/benchmark.py`, `chatrex/pcap.py` | Two-client validated echo workload, resumable matrix, CPU/timing summaries, optional per-run capture, PCAP-to-PCAPNG conversion, and wire statistics. |
| Plotting | `plot_results.py` | Reads the current `summary.csv`; produces setup, latency, CPU, and available wire-overhead plots with missing-aware error bars. |

The CLI and GUI share the same protocol/security core. This avoids a second, weaker E2E implementation in the user interface. The relay never generates or loads endpoint X25519 private identities.

### 2.2 Routed topology

The lab consists of `client`, `r1`, `r2`, and `server` network namespaces:

| Link | Subnet | Endpoint addresses |
|---|---|---|
| Client ↔ R1 | `10.0.1.0/24` | Client `10.0.1.10`; R1 `10.0.1.1` |
| R1 ↔ R2 | `10.0.2.0/24` | R1 `10.0.2.1`; R2 `10.0.2.2` |
| R2 ↔ server | `10.0.3.0/24` | R2 `10.0.3.1`; server `10.0.3.10` |

R1 and R2 enable IPv4 forwarding and use static routes. Client and server default through their adjacent router. The relay listens at `10.0.3.10`: TCP 8080 for plaintext and TCP 8443 for TLS/E2E. The benchmark sender runs in `client`; its independent echo ChatClient runs in `server` and connects to `10.0.3.10`, not localhost. Thus every sender request and returned echo crosses the routed path.

For target added RTT `R`, netem applies `R/2` to R1's inter-router egress and `R/2` to R2's inter-router egress. Requests experience the first delay and responses the second. Validation records interface addresses, routes, qdiscs, ping, and traceroute in both directions. Expected ping tolerance is the greater of 1 ms and 5% of the target, recognizing that measured RTT includes baseline path latency.

The complete device/port/trust diagram is maintained in [ARCHITECTURE.md](ARCHITECTURE.md) and supplied as a standalone vector figure in [architecture.svg](architecture.svg).

## 3. Protocol design

### 3.1 Framing and validation

TCP is a byte stream, so application messages cannot rely on one `recv()` returning one message. ChatreX prefixes each compact UTF-8 JSON object with a four-byte unsigned big-endian payload length. The receiver reads exactly four bytes and then exactly the advertised body length. Every object contains integer `v: 1` and a nonempty `type`.

The implementation rejects zero-length bodies, bodies over 1 MiB, EOF partway through a header or body, invalid UTF-8/JSON, non-object envelopes, unsupported versions, noncanonical Base64, and invalid message-specific fields. Decoded application data is limited to 65,536 bytes. These checks provide deterministic message boundaries and avoid allocating according to an unbounded peer-controlled length.

### 3.2 Registration and room lifecycle

A client first connects to the mode-appropriate listener. On TCP 8443, the accepted socket is wrapped in TLS 1.3 **before** the relay reads any registration bytes. The client requires certificate verification against `certs/ca.crt`, checks the relay hostname/IP, and verifies that the negotiated version is TLS 1.3. There is no plaintext upgrade preamble or insecure fallback. TCP 8080 accepts only `plaintext` registrations; TCP 8443 accepts only `tls` and `e2e`.

The first application frame is `register` with create/join action, mode, username, password, and room name/code. E2E registration additionally advertises a 32-byte public key. Room creation allocates a unique six-digit code and stores a 16-byte random salt plus PBKDF2-HMAC-SHA-256 digest using 200,000 iterations. Joining recomputes the digest and compares it in constant time. A successful client receives `welcome`, followed by a serialized `roster`. Roster updates advertise E2E public keys but do not make those keys trusted.

Plaintext and TLS clients use `send`; recipients receive `deliver`. Direct delivery targets a username, while `to: "*"` broadcasts to other ready members. E2E uses only individually addressed `e2e_send`/`e2e_deliver` frames. The relay validates recipient, ID, nonce, and ciphertext shape but forwards the original cryptographic strings without a private-key operation.

### 3.3 End-to-end envelope and echo workload

For each recipient, the sender creates a fresh 24-byte nonce and seals an inner JSON envelope containing version, data kind, original message ID, sender, recipient, and Base64 payload. NaCl Box combines the sender's static X25519 private key with the verified recipient public key and authenticates the ciphertext. The recipient requires a matching verified room/username/key pin, opens the Box, and checks that inner and outer metadata agree. Duplicate message IDs from a sender are rejected within the client's bounded replay window.

The benchmark uses two actual ChatClients rather than a relay-internal loopback shortcut. Echo creates a room and sender joins it. For every deterministic payload, echo checks the expected sequence ID and exact bytes, then returns the same ID and payload. Sender waits for that validated echo before issuing the next request. A run fails rather than reporting successful timing if counts, IDs, bytes, or readiness artifacts disagree.

For E2E runs, fingerprint values pass through per-run coordination files and both peers call the explicit verification API. This models a benchmark-controlled independent channel; it is not automatic roster trust. Every run uses a fresh relay and clients, and secure runs reject TLS session reuse.

## 4. Security analysis

### 4.1 Identity and explicit trust

The certificate generator creates a local RSA-2048 CA and a serverAuth certificate with SANs for `10.0.3.10`, `127.0.0.1`, and `localhost`. The CA authenticates the relay transport endpoint; it does not authenticate each chat user and does not provide E2E content encryption.

E2E identities are persistent random X25519 private keys stored with mode 0600. A fingerprint is an uppercase, grouped SHA-256 digest with a ChatreX domain separator and length-prefixed username followed by the raw public key. Binding the username into the digest discourages moving a key pin to a different display name. Trust entries are scoped by six-digit room code and username and are saved atomically with restrictive permissions.

Users run `/fingerprint` on their own client and `/peers` on the other client, compare full fingerprints through an independent authenticated channel, and only then run `/verify NAME` (or the equivalent GUI action). Any unverified current recipient blocks an E2E send. A malicious relay can withhold or alter rosters, but an honest out-of-band comparison prevents it from silently substituting a different key under the same verified fingerprint.

### 4.2 Attacker and operator visibility

| Actor / mode | Registration password | Message payload | Metadata still visible | Integrity / limitation |
|---|---|---|---|---|
| Passive network observer, plaintext | Readable | Readable after interpreting Base64 JSON fields | Addresses, rooms, usernames, recipients, IDs, timing, sizes | No transport confidentiality or integrity. |
| Active network attacker, plaintext | Readable | Readable | Same as above | Can alter, inject, replay, drop, or impersonate traffic absent other controls. |
| Passive network observer, TLS | Not visible without session secrets | Not visible | IP addresses, TCP ports, timing, record sizes, certificate handshake metadata | TLS 1.3 protects transport records; traffic analysis remains. |
| Passive network observer, TLS + E2E | Not visible without session secrets | Protected independently by NaCl Box | Same network metadata as TLS | Decrypting TLS alone would expose only E2E ciphertext and outer metadata. |
| Relay operator, plaintext | Visible during registration | Visible | Full room/roster/routing metadata | Relay can read or modify application data. |
| Relay operator, TLS | Visible during registration | Visible after TLS termination | Full room/roster/routing metadata | TLS does not provide relay-to-recipient end-to-end secrecy. |
| Relay operator, TLS + E2E | Visible during registration | Not visible if endpoint fingerprints were honestly verified | Usernames, room events, public keys, recipients, IDs, nonces, ciphertext sizes, timing | Can drop, delay, withhold roster entries, or attempt key substitution; Box modification fails and independent verification detects substitution. |
| Intended recipient | Own registration password is visible to relay | Readable by design | Endpoint-visible metadata | E2E does not protect content from the intended recipient. |
| Holder of a session TLS key log | TLS registration/content can be decrypted for logged sessions | TLS-mode content exposed; E2E inner payload remains sealed | All decrypted outer application metadata | Key logs are deliberate test-only disclosure and must never be published. |

Possession of the CA or server RSA private key does not by itself decrypt archived TLS 1.3 sessions, but can enable future server impersonation when used with an appropriate active attack/trust position. Compromise of a static E2E private identity can expose past and future Boxes computable from that identity and the relevant public keys; there is no E2E forward secrecy. Denial of service and global traffic analysis are outside the protection provided by these mechanisms.

### 4.3 Evidence-sensitive behavior

Secure benchmark runs write TLS session keys for relay, sender, and echo. These files allow Wireshark to demonstrate the difference between encrypted network records and decrypted outer application frames. They defeat the confidentiality normally expected from those test sessions and therefore require isolated credentials, restrictive handling, and exclusion from submission archives. E2E private identities are never needed to show relay opacity and must likewise remain private.

## 5. Evaluation methodology

### 5.1 Required matrix and execution

The full configuration is the Cartesian product below:

| Factor | Required values | Count |
|---|---|---:|
| Added RTT | 20, 100, 200 ms | 3 |
| Mode | Plaintext, TLS 1.3, TLS 1.3 + E2E | 3 |
| Payload | 64, 1024, 16384 bytes | 3 |
| Repetitions | Independent runs 1, 2, 3 | 3 |
| Workload | 1000 validated request/echo messages per run | 1000 |

This yields **27 conditions, 81 runs, and 81,000 sender messages**, plus the same number of returned echo payloads. Loss and jitter are zero for the required matrix. Setup supports nonzero values for separate robustness experiments, but none are claimed here.

After creating the namespace topology, the full command is:

```bash
sudo -E .venv/bin/python benchmark.py --environment lab
```

The benchmark creates a new timestamped suite, configures each RTT block, validates routing, and executes conditions sequentially. With stop-and-wait echo traffic, configured network delay alone imposes approximately:

`(20 + 100 + 200) ms × 3 modes × 3 sizes × 3 runs × 1000 = 8,640,000 ms = 144 min.`

This is a lower bound, not an ETA: registration, PBKDF2, TLS, E2E verification, local processing, capture conversion, and validation add time. The suite can resume only with an exactly matching configuration signature and matrix.

### 5.2 Timing metrics

For message `i`, sender monotonic timestamps produce:

`latency_i_ms = (recv_monotonic_ns_i - send_monotonic_ns_i) / 1,000,000`.

The send timestamp is taken immediately before the payload send; receive is taken after the matching echo and its bytes/metadata have been validated. Each run stores every observation with `echo_ok`. Per-run JSON reports count, mean, sample standard deviation, median, p95, p99, minimum, and maximum. Suite `summary.csv` reports the mean and sample standard deviation **across successful run-level means**, not a pooled claim that hides run variability. Per-run latency spread remains available in `runs.csv` and `run.json`.

Sender setup includes the full `ChatClient.connect` path and, for E2E, explicit peer-verification coordination. Detailed fields distinguish TCP connect, TLS handshake, registration, key generation, basic ChatClient total, peer verification, and overall setup. `setup_rtt_ratio = total_setup_ms / configured_rtt_ms` is defined only for nonzero RTT. Echo setup is separately available in worker artifacts; the summary's setup metric is the sender's.

### 5.3 CPU metrics

Client CPU is sender-process user + system CPU from `resource.getrusage`; relay CPU is the exact relay PID's user + system jiffies from `/proc/<pid>/stat`. Setup, message-phase, and total seconds are recorded, along with message-phase CPU milliseconds per message. Echo CPU is also retained in `run.json` for interpretation, although the main summary focuses on sender and relay.

These are process CPU times, not whole-machine utilization percentages. Short smoke runs are especially affected by scheduler/timer resolution and should not be used to rank modes. Full runs reduce, but do not eliminate, measurement noise; three-run sample spread must accompany means.

### 5.4 Wire-byte metric and capture

With capture enabled, `tcpdump` listens on `r1/veth-r1-b` using `host 10.0.3.10 and tcp port 8080` for plaintext or port 8443 for secure modes. Both directions of the sender/relay flow cross this interface. The classic capture is converted to `capture.pcapng` and inspected with `chatrex.pcap.wire_statistics`.

For `N` messages of `S` bytes:

`wire_ratio = (C2S_original_frame_bytes + S2C_original_frame_bytes) / (2 × N × S)`.

The denominator counts the request payload and equal-sized returned echo exactly once each. The numerator includes session setup/teardown, link/IP/TCP headers, ACKs, TLS records, framing, and observed retransmissions. Original capture frame lengths normally exclude Ethernet FCS, preamble, and inter-frame gap. Retransmission and duplicate-ACK counts are documented heuristics, not substitutes for full TCP reconstruction. Local loopback captures are deliberately excluded because duplicate flows invalidate this ratio.

### 5.5 Reproducibility and evidence controls

- `manifest.json` records the exact matrix, seed, environment, software versions, capture policy, configuration hash, and completion counters.
- `run.json` links each result to raw latencies, logs, readiness/completion checks, key logs, capture, and versions.
- A complete manifest is complete only for its declared configuration; a three-run smoke manifest is not an 81-run evaluation.
- `summary.csv` leaves spread undefined with fewer than two successful values and leaves wire metrics null when capture is disabled. Null is not zero.
- `results/agent-smoke/` is the only genuine current benchmark suite used in this report. Legacy root PCAP/text files are not treated as new routed evidence.
- Final evidence must include full topology validation, PCAPNG files, annotated mode-specific screenshots, and curated hashes/paths as described in [EVIDENCE_GUIDE.md](EVIDENCE_GUIDE.md).

## 6. Results

### 6.1 Full routed evaluation — PENDING

**No full routed run has been performed.** The table below is the required result grid, not a set of estimates. Every numeric cell remains `PENDING`; `0 / 3` records the current full-suite evidence count. After execution, each metric cell should contain **mean ± sample SD across the three successful runs**, with failed runs and missing captures disclosed rather than silently omitted.

| RTT (ms) | Mode | Size (B) | Runs | Setup (ms) | Message RTT (ms) | Wire / payload | Client total CPU (s) | Relay total CPU (s) |
|---:|---|---:|---:|---|---|---|---|---|
| 20 | Plaintext | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | Plaintext | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | Plaintext | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | TLS 1.3 | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | TLS 1.3 | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | TLS 1.3 | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | TLS + E2E | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | TLS + E2E | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 20 | TLS + E2E | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | Plaintext | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | Plaintext | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | Plaintext | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | TLS 1.3 | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | TLS 1.3 | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | TLS 1.3 | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | TLS + E2E | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | TLS + E2E | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 100 | TLS + E2E | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | Plaintext | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | Plaintext | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | Plaintext | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | TLS 1.3 | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | TLS 1.3 | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | TLS 1.3 | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | TLS + E2E | 64 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | TLS + E2E | 1024 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |
| 200 | TLS + E2E | 16384 | 0 / 3 | PENDING | PENDING | PENDING | PENDING | PENDING |

The final results section must additionally provide:

1. setup/RTT ratio or an equivalent setup-versus-RTT plot with three-run spread;
2. per-run latency sample SD and p95/p99 (available in `runs.csv`/`run.json`) alongside the between-run summary;
3. client and relay setup/message CPU seconds and CPU ms/message from `summary.csv`, not only total CPU;
4. capture-backed wire-ratio mean and spread, plus any retransmission/duplicate-ACK anomalies;
5. actual measured ping RTT and validation status for each RTT block;
6. explicit completion count (`81 / 81`) and disclosure of any resumed, failed, or missing run; and
7. the common architecture figure and annotated plaintext, TLS, and E2E capture screenshots with traceable run paths.

### 6.2 Genuine local smoke results — not the full evaluation

The existing suite at `results/agent-smoke/` has `environment: local`, RTT 0 ms, payload 64 B, five messages, one run per mode, seed 123, and capture disabled. It contains **3 runs and 15 sender messages total**. The following values are copied from its `summary.csv`; within-run message SD comes from the corresponding `runs.csv`. Rounding is for presentation only and does not replace the raw artifacts.

| Mode | Sender setup (ms) | Message mean (ms) | Within-run msg SD (ms), n=5 | Client setup CPU (s) | Client msg CPU (ms/msg) | Relay setup CPU (s) | Relay msg CPU (ms/msg) | Wire ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Plaintext | 37.518053 | 1.139278 | 0.329459 | 0.000816 | 0.307200 | 0.030000 | 2.000000 | N/A — capture disabled |
| TLS 1.3 | 59.317355 | 1.068436 | 0.432786 | 0.003703 | 0.284400 | 0.020000 | 0.000000 | N/A — capture disabled |
| TLS + E2E | 109.557867 | 3.035709 | 1.599768 | 0.005486 | 1.125000 | 0.030000 | 2.000000 | N/A — capture disabled |

Client total CPU was 0.003775 s (plaintext), 0.006960 s (TLS), and 0.013574 s (E2E); relay total CPU was 0.060000, 0.050000, and 0.070000 s respectively. Between-run mean/spread is undefined because there is only one run per condition. The relay message CPU values of 0 or 10 ms total for five messages also demonstrate the coarse `/proc` tick resolution at this scale; they must not be interpreted as precise zero cost or a reliable E2E ranking.

The smoke suite establishes that the orchestration produced validated echoes in all three modes, negotiated TLS 1.3 without session reuse in secure runs, and performed explicit two-way fingerprint verification in the E2E run. It does **not** establish routed reachability, delay accuracy, 1000-message stability, size/RTT trends, wire overhead, three-run spread, or production performance. In particular, the lower TLS mean than plaintext in this tiny sample is not evidence that TLS is generally faster.

### 6.3 Analysis awaiting full data

The following are **analysis plans, not observed findings**:

- Compare setup medians/means and spread across RTT within each mode, and decompose TCP, TLS, registration, and E2E verification phases before attributing cost to cryptography.
- Compare message latency with measured ping RTT. Sequential stop-and-wait traffic should be interpreted as application round-trip behavior, not throughput under concurrent load.
- Inspect whether larger payloads amortize fixed framing/TLS overhead, while retaining the exact numerator definition and noting retransmissions or capture anomalies.
- Compare CPU per message after the 1000-message warm workload; do not extrapolate from five-message smoke CPU counters.
- Use screenshots to verify, rather than infer, plaintext readability, TLS record opacity, keylog-assisted outer decoding, and E2E ciphertext opacity at the relay.

No plots derived from the legacy root text/captures are included as current results. New figures are **PENDING** generation from a validated full suite or a documented, lossless export.

## 7. Discussion

The design separates two trust decisions that are often conflated. The local CA tells a client which relay terminates TLS; fingerprint verification tells an E2E client which endpoint public key may receive content. TLS-only mode intentionally trusts the relay with plaintext, whereas E2E mode limits the relay to routing ciphertext and metadata. This distinction is visible in both protocol types and the capture plan.

The measurement design likewise separates setup from steady-state behavior. TLS handshake and registration round trips should be evaluated through the setup metrics, while NaCl Box processing and expanded ciphertext should be evaluated through message-phase CPU and wire statistics. E2E setup includes explicit verification coordination, so a simplistic comparison against only the TLS handshake would misattribute the measured work. Reporting the detailed phases prevents that ambiguity.

The stop-and-wait echo workload favors correctness and attribution over throughput. Every returned value must match the request ID and bytes, and every condition has independently inspectable raw latencies. The tradeoff is that results will not represent concurrent-room throughput or multiple outstanding messages. Relay CPU also covers one controlled run at a time and should not be generalized to a heavily loaded multi-room service without another experiment.

Three repetitions provide a minimal indication of run-to-run variability, not strong distributional confidence. Outliers and failed runs must be shown. The correct conclusion may be that a difference is small relative to observed spread; the full data, rather than the implementation's security features alone, must determine that judgment.

## 8. Limitations and threats to validity

1. **Full routed evidence is absent.** Root privileges and `tshark` are unavailable in the current environment. No new routed PCAPNG files, annotated routed screenshots, or 81-run metrics have been produced. Code readiness and local smoke success are not substitutes.
2. **Smoke scale is deliberately inadequate for performance claims.** It has only five 64-byte messages, one run per mode, and 0 ms local RTT. There is no between-run spread and no valid wire ratio.
3. **Only three repetitions are specified.** Three-run sample standard deviation is useful but statistically limited. Scheduling, host load, kernel versions, and hardware can affect external validity.
4. **Static X25519 identities lack E2E forward secrecy and post-compromise security.** There is no ephemeral Double Ratchet/session-key rotation protocol. A compromised static private key threatens applicable historical and future messages.
5. **Metadata remains visible.** Even verified E2E exposes registration credentials to the relay, as well as usernames, public keys, room membership, recipients, message IDs, nonces, ciphertext sizes, and timing. Network observers retain traffic-analysis data.
6. **TLS key logging is a testing exception.** It enables decryption of corresponding TLS sessions and TLS-mode content. It does not decrypt inner NaCl Boxes, but the key logs are secrets and must never be published or enabled for real user traffic.
7. **The local CA is laboratory trust infrastructure.** It is not a production public PKI, revocation system, or multi-device identity recovery design. Server/CA private keys require strict exclusion from archives.
8. **Wire accounting has defined boundaries.** It uses original frame lengths at one routed interface and excludes physical preamble/FCS/inter-frame gap. Retransmission/duplicate-ACK detection is heuristic. Loopback capture is invalid for this metric.
9. **The workload is sequential and two-client.** It does not measure concurrent throughput, many-room scalability, internet path diversity, or resistance to active denial of service.
10. **Evidence screenshots are still to be collected.** A protocol field in source code is not visual capture proof. The final submission must not fabricate or reuse unverified legacy traces to fill this gap.

## 9. Conclusion

ChatreX implements the requested framing, relay/client modes, local-CA TLS 1.3, explicitly verified X25519/NaCl Box E2E messaging, routed topology automation, and detailed benchmark/artifact schema. The 122 passing tests and three-mode local smoke suite support implementation readiness and basic functional correctness. The architecture and report define how the full 81-run experiment should be executed and analyzed without confusing transport trust with end-to-end trust.

The required experimental conclusion remains **PENDING**. A valid final submission still needs the privileged routed matrix, measured RTT validation, 1000-message/three-run summaries, frame-byte/payload measurements, PCAPNG files, and annotated per-mode evidence. Those artifacts must be generated and reviewed before making claims about latency trends, overhead rankings, or completion of every Project 2 requirement.

## References and implementation pointers

- M. Rescorla, **RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3**.
- A. Langley, M. Hamburg, and S. Turner, **RFC 7748: Elliptic Curves for Security** (X25519).
- PyNaCl `nacl.public.Box` and Python `ssl` documentation, as used by `chatrex/security.py`.
- Project protocol and behavior: `chatrex/protocol.py`, `chatrex/relay.py`, `chatrex/client.py`, and `chatrex/security.py`.
- Measurement definitions and authoritative schemas: `chatrex/benchmark.py` and `chatrex/pcap.py`.

## Appendix A — Final evidence insertion index

When the privileged lab has completed, update this report using only traceable artifacts:

| Report item | Required source | Current state |
|---|---|---|
| Matrix completion and software environment | `results/<UTC>-lab/manifest.json` | PENDING |
| 27 condition summaries | `results/<UTC>-lab/summary.csv` and `runs.csv` | PENDING |
| Detailed latency/setup/CPU phases | Per-condition `run-*/run.json` and `latencies.csv` | PENDING |
| Wire ratios and captures | Per-run `capture.pcapng`, `capture.log`, `wire_statistics` | PENDING |
| RTT and routing validation | `topology/rtt-*/topology_summary.txt`, ping, traceroute, qdisc files | PENDING |
| Annotated screenshots | Curated evidence produced according to EVIDENCE_GUIDE | PENDING |
| Plots | New full-suite plots with stated input/export method | PENDING |
| Local functional cross-check | `results/agent-smoke/manifest.json`, `summary.csv`, `runs.csv` | Smoke-verified only |

## Appendix B — Disclosure and publication check

The separate [AI-use disclosure](AI_USE.md) describes assistance and verification boundaries. Before submission, remove private keys, E2E identity/trust files, TLS key logs, real credentials, and unreviewed captures. Do not publish legacy root keys/traces. Preserve enough sanitized raw data and capture hashes for an examiner to reproduce every reported number, and revise the abstract, results, discussion, conclusion, and checklist together so no section overstates completion.
