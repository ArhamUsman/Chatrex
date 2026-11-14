# ChatreX — Project 2

ChatreX is a TCP room relay with CLI and NiceGUI clients, three security modes, a two-router Linux network-namespace lab, and a resumable benchmark pipeline.

> **Evaluation status:** the implementation and 123 tests are ready, and `results/agent-smoke/` contains a genuine **local smoke test only** (3 runs total; 5 messages, 64 B, 0 ms RTT, 1 run per mode). The required routed 81-run evaluation, new routed PCAPNG files, and annotated screenshots have **not** been run in this environment because root privileges and `tshark` are unavailable. Full results are **PENDING**, not implied by the smoke data.

## Documentation

- [Architecture, addressing, protocol flow, and trust boundaries](docs/ARCHITECTURE.md)
- [Technical report](docs/TECHNICAL_REPORT.md)
- [Packet-capture and screenshot evidence guide](docs/EVIDENCE_GUIDE.md)
- [Requirements and evidence checklist](docs/REQUIREMENTS_CHECKLIST.md)
- [AI-use disclosure](docs/AI_USE.md)

## 1. Quickstart

Use Linux with Python 3.10+ and OpenSSL. The routed lab additionally requires `ip`, `tc`, `ping`, `traceroute`, root privileges, and—for packet evidence—`tcpdump`; Wireshark/`tshark` are needed for capture inspection.

From the project root:

```bash
cd "/home/fad/Projects/project v3"
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Generate the local CA and relay certificate in `certs/`:

```bash
./gen_certs.sh
```

The script refuses to overwrite an existing CA/server set. `certs/server.crt` includes identities for `10.0.3.10`, `127.0.0.1`, and `localhost`. Regeneration with `./gen_certs.sh certs --force` replaces the CA and server credentials and invalidates the previous trust configuration; use it deliberately.

## 2. Local relay and two CLI clients

All commands below run from the project root. Use separate terminals.

**Terminal 1 — relay, bound only to loopback:**

```bash
.venv/bin/python server.py --host 127.0.0.1
```

**Terminal 2 — Alice creates an E2E room:**

```bash
.venv/bin/python client.py --host 127.0.0.1 --username alice --mode e2e --create demo
```

Enter a lab-only room password when prompted. Alice's terminal displays the actual six-digit room code.

**Terminal 3 — Bob joins that room** (replace `123456` with Alice's displayed code):

```bash
.venv/bin/python client.py --host 127.0.0.1 --username bob --mode e2e --join 123456
```

E2E sending is intentionally blocked until every recipient is verified. Perform these steps explicitly:

1. In **each** client, run `/fingerprint` and share the full value with the other user through a separate authenticated channel.
2. In **each** client, run `/peers` and compare the peer's full fingerprint with the independently supplied value.
3. Only after a match, Alice runs:

   ```text
   /verify bob
   ```

   and Bob runs:

   ```text
   /verify alice
   ```

4. Type a message. `/help` lists all commands; `/quit` leaves the room.

Never approve a fingerprint supplied only through the relayed chat. Trust pins are scoped by room code and username under `user_data/`.

For the other modes, use `--mode plaintext` (TCP 8080) or `--mode tls` (TCP 8443), with the same mode for creator and joiner. Plaintext is an insecure measurement baseline: room credentials and messages are exposed on the network. TLS authenticates the relay and protects transport, but the relay can read messages.

## 3. NiceGUI web client

With a relay already running, start the dashboard in another terminal:

```bash
.venv/bin/python main.py --host 127.0.0.1 --port 8081 --relay-host 127.0.0.1
```

Open <http://127.0.0.1:8081>. The dashboard does **not** start a relay. Its default relay is the routed-lab address `10.0.3.10`; the command above overrides it for local use. Port 8081 is the local web interface, not a relay listener. In E2E mode, expand each peer's full fingerprint, compare it out of band, and use the explicit verification action before sending.

## 4. Routed two-router lab

The scripts create/remove only the namespaces `client`, `r1`, `r2`, and `server`. Setup removes any pre-existing namespaces with those exact names. Review [the architecture](docs/ARCHITECTURE.md) before running privileged commands.

From the project root, create the topology and save independent validation evidence:

```bash
cd "/home/fad/Projects/project v3"
sudo ./setup_topology.sh 20 0 0
sudo env EXPECTED_RTT_MS=20 ./validate_topology.sh results/topology-rtt20
```

Arguments are `[RTT_MS] [LOSS_PERCENT] [JITTER_MS]`; the required measurement matrix uses zero loss and jitter. The setup applies `RTT/2` to each inter-router egress and checks ping and traceroute in both directions.

To exercise the CLI in the lab, start the relay in the server namespace:

```bash
sudo ip netns exec server "/home/fad/Projects/project v3/.venv/bin/python" "/home/fad/Projects/project v3/server.py" --host 0.0.0.0 --cert "/home/fad/Projects/project v3/certs/server.crt" --key "/home/fad/Projects/project v3/certs/server.key"
```

In two other terminals, run Alice and Bob in the client namespace, always using the routed address—**never `localhost` or `127.0.0.1` in the lab**:

```bash
sudo ip netns exec client "/home/fad/Projects/project v3/.venv/bin/python" "/home/fad/Projects/project v3/client.py" --host 10.0.3.10 --username alice --mode e2e --create routed-demo --ca "/home/fad/Projects/project v3/certs/ca.crt"
```

```bash
sudo ip netns exec client "/home/fad/Projects/project v3/.venv/bin/python" "/home/fad/Projects/project v3/client.py" --host 10.0.3.10 --username bob --mode e2e --join 123456 --ca "/home/fad/Projects/project v3/certs/ca.crt"
```

Replace the example room code and repeat the `/fingerprint`, `/peers`, out-of-band comparison, and `/verify NAME` procedure above.

Remove the lab when finished:

```bash
sudo ./teardown_topology.sh
```

## 5. Benchmarks

### Full required matrix — pending privileged execution

Stop manually started relay/clients first; the benchmark launches its own relay, sender, and echo client for every run. Create the lab with `sudo ./setup_topology.sh 20 0 0`, ensure `tcpdump` is installed for automatic lab captures, then run exactly:

```bash
sudo -E .venv/bin/python benchmark.py --environment lab
```

The defaults are 3 RTTs × 3 modes × 3 payload sizes × 3 repetitions = **81 runs and 81,000 sender messages** (plus 81,000 validated echo payloads and protocol traffic):

| Dimension | Values |
|---|---|
| Added network RTT | 20, 100, 200 ms |
| Modes | `plaintext`, `tls`, `e2e` |
| Payloads | 64, 1024, 16384 bytes |
| Messages per run | 1000 |
| Repetitions per condition | 3 |

Messages are sequential request/validated-echo exchanges. The configured network delay alone gives a **~144 minute lower bound**: `(20 + 100 + 200) ms × 9 mode/size combinations × 3 runs × 1000 messages = 8640 s`. Setup, TLS, PBKDF2, processing, capture, and validation make the real run longer.

Output goes to a new `results/<UTC timestamp>-lab/` directory. The benchmark replaces and validates netem once per RTT block; it does not create or delete namespaces. Lab capture is automatic when `tcpdump` is available. Add `--capture` to make missing `tcpdump` a fatal configuration error, or `--no-capture` only for a deliberately incomplete diagnostic run.

Resume only an exactly matching full configuration:

```bash
sudo -E .venv/bin/python benchmark.py --environment lab --resume results/<UTC timestamp>-lab
```

Do not rename a reduced suite or resume it as a full evaluation: configuration signatures and the manifest prevent that mistake.

### Reduced local smoke test

Use a **new** output directory and keep the word `smoke` in its name:

```bash
.venv/bin/python benchmark.py --environment local --messages 5 --runs 1 --rtts 0 --sizes 64 --seed 123 --output results/local-smoke
```

This produces only 3 runs/15 sender messages and no wire ratios. Local loopback capture is disabled because duplicate loopback flows invalidate the ratio. Smoke output verifies orchestration and basic functionality; it is not the Project 2 performance evaluation. The existing `results/agent-smoke/` is one such suite.

### Plotting

```bash
.venv/bin/python plot_results.py results/<UTC timestamp>-lab
```

`plot_results.py` reads the benchmark's `summary.csv` and writes high-DPI `setup_vs_rtt.png`, `latency_by_size.png`, `cpu_overhead.png`, and—when routed wire measurements exist—`wire_overhead.png` into the experiment's `plots/` directory. Use `--output DIR` to choose another destination. Missing metrics remain missing rather than being plotted as zero. For the included local smoke plots, run `.venv/bin/python plot_results.py results/agent-smoke`.

## 6. Output schema

Each suite has this structure:

| Artifact | Meaning |
|---|---|
| `manifest.json` | Exact configuration/signature, software versions, intended matrix, architecture, capture policy, completion counters, and fatal errors. `status: complete` is meaningful only for that manifest's stated matrix. |
| `runs.csv` | One row per run: condition, run number, status/error, timestamps, setup/latency statistics, client and relay CPU, wire ratio, configured/measured RTT, capture and latency paths, and resume status. |
| `summary.csv` | One row per condition with successful/failed/running counts and `<metric>_mean` plus `<metric>_sample_sd` across successful runs. |
| `rtt-<N>ms_<mode>_<size>B/run-<R>/run.json` | Detailed setup phases, TLS version/session reuse, E2E verification flags, latency distribution, client/echo/relay CPU, wire statistics, capture metadata, versions, and artifact paths. |
| `.../latencies.csv` | `run_id,seq,send_monotonic_ns,recv_monotonic_ns,latency_ms,echo_ok`; one validated row per sender message. |
| `.../capture.pcapng` | Routed capture when enabled; `capture.log` records capture status. |
| `.../*.log`, readiness/done JSON | Relay/client logs and independent orchestration checks. |
| `topology/rtt-<N>ms/` | Netem qdiscs, bidirectional addresses/routes/ping/traceroute, measured RTT, and validation result. |
| `.../*-tls.keys` | Sensitive TLS session key logs generated for secure benchmark runs. **Test-only; never publish.** |

`summary.csv` aggregates these metrics, each with mean and sample standard deviation where at least two values exist: setup ms, message latency ms (mean of per-run means), client setup/message/total CPU seconds, client CPU ms/message, relay setup/message/total CPU seconds, relay CPU ms/message, and wire ratio. Blank/null means unavailable or not defined (for example, one-run spread or disabled capture), **not zero**.

The wire ratio is `(client→server frame bytes + server→client frame bytes) / (2 × messages × payload bytes)`. It includes both echo directions, setup/teardown, Ethernet/IP/TCP headers, ACKs, TLS records, framing, and retransmissions; ordinary frame lengths exclude Ethernet FCS, preamble, and inter-frame gap.

## 7. Tests

From the project root:

```bash
.venv/bin/python -m pytest -q
```

Current result: **123 passed**. Tests cover framing, protocol validation, TLS/E2E security, integration behavior, PCAP/PCAPNG handling, and benchmark aggregation/resume safeguards. They do not replace privileged routed-lab evidence.

## 8. Security and trust boundaries

| Mode | Network observer | Relay |
|---|---|---|
| Plaintext | Can observe/modify registration, room credentials, metadata, and message content. | Same visibility and control. |
| TLS 1.3 | Sees addresses, ports, timing, and sizes; application content is transport-encrypted. | Terminates TLS and can read room credentials and messages. |
| TLS 1.3 + E2E | Sees TLS metadata only. | Sees registration credentials, usernames, public keys, recipients, message IDs, nonces, ciphertext lengths, and timing, but not verified message plaintext. |

The secure listener performs TLS immediately after accept; no plaintext registration precedes it. TLS and E2E use port 8443, while plaintext uses a separate 8080 listener. E2E uses persistent X25519 identities, explicit SHA-256 fingerprint verification, fresh 24-byte nonces, and an authenticated NaCl Box sealed separately for each recipient. Trust is never automatic.

Important limits: static X25519 E2E keys provide no E2E forward secrecy; relay-visible metadata remains; a recipient can read messages by design; and TLS key logs enable decryption of the corresponding TLS sessions but not the inner NaCl Boxes. Key logging is for controlled evidence collection only.

## 9. Legacy material and publication safety

The old **root-level** `ca.key`, `server.key`, `sslkeylog.txt`, `wire_*.pcap`, and `wire_results.txt` are **legacy artifacts**. They must not be published or cited as new routed evidence. Do not publish any private key (`*.key`), E2E identity, trust store, TLS key log (`*.keys`/`sslkeylog.txt`), room password, or unreviewed capture containing sensitive credentials. Use only newly generated lab credentials and curated, annotated PCAPNG/screenshots for submission evidence. See [EVIDENCE_GUIDE.md](docs/EVIDENCE_GUIDE.md).
