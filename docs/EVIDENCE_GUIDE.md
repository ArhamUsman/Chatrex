# Evidence guide: routed captures, screenshots, and traces

> **Current evidence status:** no new routed PCAPNG files or annotated screenshots have been produced in this environment. Root privileges and `tshark` are unavailable. The procedures below are for the privileged evidence run, not a claim that those steps have completed. `results/agent-smoke/` is local smoke evidence only and cannot satisfy the routed capture requirements.

## 1. Evidence set and naming

Run the full lab into a new `results/<UTC timestamp>-lab/` directory. Preserve its raw artifacts and curate only reviewed copies for submission.

Set these variables to the **actual** suite/run before using the examples; replace the placeholder suite name first:

```bash
cd "/home/fad/Projects/project v3"
SUITE="/home/fad/Projects/project v3/results/REPLACE_WITH_UTC_TIMESTAMP-lab"
RUN="$SUITE/rtt-20ms_tls_64B/run-1"
TRACE="$RUN/capture.pcapng"
KEYS="$RUN/relay-tls.keys"
test -f "$TRACE" || printf 'Missing routed capture: %s\n' "$TRACE"
```

A complete evidence set should contain:

- the common [architecture diagram](architecture.svg);
- `manifest.json`, `runs.csv`, and `summary.csv` for the exact full suite;
- per-run `run.json`, `latencies.csv`, logs, and `capture.pcapng` when capture is enabled;
- `topology/rtt-{20,100,200}ms/` address, route, qdisc, ping, traceroute, and validation files;
- annotated screenshots for plaintext, TLS, and E2E, plus explicit fingerprint verification;
- capture metadata/hashes and a mapping from every screenshot to its suite, condition, run, packet/stream, and annotations; and
- no private keys, E2E identity/trust files, TLS key logs, or real credentials in the public evidence bundle.

Suggested future screenshot paths are `docs/evidence/01-topology-addressing.png`, `docs/evidence/10-plaintext-stream.png`, and so on in the checklist below. These files do **not** currently exist; create them only from genuine evidence.

## 2. Automatic per-run benchmark capture

### 2.1 Prerequisites and execution

Install/prepare the lab tools on the evidence machine, generate lab-only certificates, and verify that `tcpdump` is available. Then:

```bash
cd "/home/fad/Projects/project v3"
sudo ./setup_topology.sh 20 0 0
sudo env EXPECTED_RTT_MS=20 ./validate_topology.sh results/topology-rtt20
sudo -E .venv/bin/python benchmark.py --environment lab --capture
```

The required full benchmark command without the optional fail-closed capture flag is documented in README. `--capture` makes unavailable `tcpdump` an error instead of silently producing a suite without wire evidence. Do not run another relay on ports 8080/8443 while the benchmark is running.

### 2.2 What the benchmark records

For each run it launches, before starting the relay:

```text
ip netns exec r1 tcpdump -i veth-r1-b -s 0 -U -w capture.pcap \
  'host 10.0.3.10 and tcp port PORT'
```

`PORT` is 8080 for plaintext and 8443 for TLS/E2E. On completion, the benchmark stops capture, calculates wire statistics for `10.0.1.10 ↔ 10.0.3.10`, converts the classic PCAP to `capture.pcapng`, and removes the intermediate PCAP. It stores capture readiness/shutdown details in `capture.log`.

Inspect each `run.json` for:

- `capture.enabled: true` and the expected interface/filter;
- `wire_statistics` rather than `null`;
- `capture.pcapng` in `artifacts`;
- `status: success`, all expected messages, and valid echo checks; and
- matching condition, run ID, RTT block, payload size, and capture denominator.

Do not infer capture success merely from a filename. Use `capinfos`/Wireshark and compare the capture with the run metadata.

## 3. Manual `tcpdump` procedure for supplementary evidence

Use a separate manual directory so a benchmark artifact is never overwritten. Start the capture immediately before the selected client/session and stop it with **Ctrl+C** only after the session has closed cleanly.

```bash
cd "/home/fad/Projects/project v3"
CAP="/home/fad/Projects/project v3/results/manual-evidence"
sudo mkdir -p "$CAP"
```

**Plaintext, port 8080:**

```bash
sudo ip netns exec r1 tcpdump -i veth-r1-b -s 0 -U -w "$CAP/plaintext-rtt20-64B-run1.pcap" 'host 10.0.3.10 and tcp port 8080'
```

**TLS or E2E, port 8443:**

```bash
sudo ip netns exec r1 tcpdump -i veth-r1-b -s 0 -U -w "$CAP/secure-rtt20-64B-run1.pcap" 'host 10.0.3.10 and tcp port 8443'
```

Use distinct filenames for every mode/condition/run. After stopping `tcpdump`, note its packet counts and any “dropped by kernel” warning. Convert to PCAPNG with Wireshark's `editcap`:

```bash
editcap "$CAP/secure-rtt20-64B-run1.pcap" "$CAP/secure-rtt20-64B-run1.pcapng"
```

Or use the project's tested converter:

```bash
.venv/bin/python -c 'import sys; from chatrex.pcap import convert_pcap_to_pcapng; convert_pcap_to_pcapng(sys.argv[1], sys.argv[2])' "$CAP/secure-rtt20-64B-run1.pcap" "$CAP/secure-rtt20-64B-run1.pcapng"
```

Record a hash and metadata after conversion:

```bash
sha256sum "$CAP/secure-rtt20-64B-run1.pcapng"
capinfos "$CAP/secure-rtt20-64B-run1.pcapng"
```

For valid wire ratios, prefer the benchmark's automated run boundaries and accounting. A manual capture containing extra sessions or unrelated messages cannot be divided by one run's payload denominator without a separately justified flow/session analysis.

## 4. Topology and traceroute evidence

The preferred method is the validation script, which saves both command output and a pass/fail summary:

```bash
cd "/home/fad/Projects/project v3"
sudo env EXPECTED_RTT_MS=20 ./validate_topology.sh results/topology-rtt20
```

For each 100 and 200 ms RTT block, the benchmark performs equivalent validation under `$SUITE/topology/`. If repeating manually after applying the corresponding netem, use `EXPECTED_RTT_MS=100` or `200` and a distinct output directory.

Direct commands for terminal evidence are:

```bash
sudo ip netns exec client ip addr show
sudo ip netns exec client ip route show
sudo ip netns exec server ip addr show
sudo ip netns exec server ip route show
sudo ip netns exec r1 tc -s qdisc show dev veth-r1-b
sudo ip netns exec r2 tc -s qdisc show dev veth-r2-b
sudo ip netns exec client ping -n -c 5 -W 2 10.0.3.10
sudo ip netns exec server ping -n -c 5 -W 2 10.0.1.10
sudo ip netns exec client traceroute -n -w 1 -q 1 10.0.3.10
sudo ip netns exec server traceroute -n -w 1 -q 1 10.0.1.10
```

Verify and annotate the actual route, rather than copying labels if output differs:

| Direction | Expected routed hops |
|---|---|
| Client `10.0.1.10` → server `10.0.3.10` | R1 `10.0.1.1` → R2 `10.0.2.2` → server `10.0.3.10` |
| Server `10.0.3.10` → client `10.0.1.10` | R2 `10.0.3.1` → R1 `10.0.2.1` → client `10.0.1.10` |

Screenshots must include the actual command prompt/output and be accompanied by the script's text artifacts. A terminal screenshot alone does not replace machine-readable validation. Annotate both `D = RTT/2` qdiscs, both ping averages, and all router hops; do not label configured RTT as measured RTT.

## 5. Wireshark inspection by mode

Open a trace with:

```bash
wireshark "$TRACE"
```

Useful display filters:

```text
ip.addr == 10.0.1.10 && ip.addr == 10.0.3.10 && tcp.port == 8080
ip.addr == 10.0.1.10 && ip.addr == 10.0.3.10 && tcp.port == 8443
tcp.len > 0
tls.handshake
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
```

Use **Analyze → Follow → TCP Stream** on the actual selected stream. Record the real `tcp.stream` index; never assume stream 0 in annotations. Include packet list, packet details, source/destination, ports, and enough context to reproduce the observation.

### 5.1 Plaintext — TCP 8080

1. Select the routed plaintext stream and confirm source/destination `10.0.1.10 ↔ 10.0.3.10`.
2. Follow the TCP stream. Identify the four-byte length prefix and versioned JSON registration/send/deliver records.
3. Show that registration credentials and application fields are transport-readable. Message bytes are Base64 inside `data`; annotate this accurately rather than claiming that arbitrary payload bytes appear as literal text.
4. Include a `send`/`deliver` pair or the benchmark's matching request/echo message ID. Cross-check a known lab payload by decoding Base64 separately if needed.
5. Capture the screenshot without a TLS key log profile. Label it `PLAINTEXT — insecure baseline`, with RTT, payload size, run, stream, and frame numbers.

Use only a known disposable lab password. Redact a reused secret only in a curated screenshot; never alter the raw trace or present redaction as protocol encryption.

### 5.2 TLS 1.3 — TCP 8443

First produce the **network observer view without key logging**:

1. Select ClientHello/ServerHello and annotate the `supported_versions` TLS 1.3 negotiation and the local-CA server certificate.
2. Show post-handshake encrypted application records on port 8443. Registration and chat fields should not be visible as plaintext.
3. Save the handshake and opaque-application screenshots with actual frame numbers.

Then load the correct test key log as described in section 6 and reopen/reload the capture:

4. Follow/decode the same TLS session and annotate registration plus `send`/`deliver` outer JSON. Explain that this visibility is deliberately enabled by the key log and mirrors what the TLS-terminating relay can access.
5. Save a separate `keylog-assisted` screenshot. Never include the key log itself in the public screenshot or bundle.

Also preserve application-side proof of certificate verification, such as the `gen_certs.sh` verification output or a successful client using only `certs/ca.crt`; a Wireshark handshake alone does not prove the client accepted the intended identity.

### 5.3 TLS 1.3 + E2E — TCP 8443

1. Without key logging, show the same TLS network opacity as TLS mode.
2. With the relay/sender key log loaded, decode the outer session and identify `e2e_send` and `e2e_deliver`.
3. Annotate visible outer metadata (`from`/`to` as applicable, `id`, `nonce`, `ciphertext`) and emphasize that the inner Base64 `data` envelope is not visible. The relay still cannot open the NaCl Box with TLS secrets.
4. Correlate the ciphertext frame with an endpoint screenshot showing the exact received message, without exposing either private identity.
5. Capture `/fingerprint`, `/peers`, the independent comparison, and explicit `/verify NAME` (or the GUI equivalents). Show full fingerprints or enough side-by-side context to demonstrate that the complete values were compared; do not imply that clicking Verify alone authenticated a key.
6. Label every screenshot `TLS 1.3 + E2E`, with run/RTT/size and keylog state. TLS key logging reveals outer frames only; it is not E2E decryption.

## 6. TLS key-log use — controlled testing only

The benchmark automatically writes `relay-tls.keys`, `sender-tls.keys`, and `echo-tls.keys` for secure runs. For a routed capture at R1, `relay-tls.keys` is normally the most useful because the relay logs its server-side session secrets; `sender-tls.keys` should contain the corresponding routed sender session.

In Wireshark:

1. Open **Edit → Preferences → Protocols → TLS**.
2. Set **(Pre)-Master-Secret log filename** to the absolute key-log path, for example `$RUN/relay-tls.keys` after expanding the variable manually.
3. Reopen the capture or reload the TLS dissection. Confirm that decryption applies to the intended stream.
4. Remove the setting or use a separate no-keylog profile to reproduce the network-observer screenshots.

For manual applications, `server.py` and `client.py` accept `--keylog PATH`. For example, this routed TLS client logs its own session while creating a disposable room:

```bash
sudo ip netns exec client env SSLKEYLOGFILE="$CAP/sender-tls.keys" "/home/fad/Projects/project v3/.venv/bin/python" "/home/fad/Projects/project v3/client.py" --host 10.0.3.10 --username alice --mode tls --create evidence --ca "/home/fad/Projects/project v3/certs/ca.crt" --keylog "$CAP/sender-tls.keys"
```

`SSLKEYLOGFILE` is also honored by the shared TLS context; the explicit `--keylog` above makes the evidence intent clear. Do not enable either mechanism for real conversations.

**Publication rule:** key logs, CA/server private keys, E2E identities, and trust stores are secrets. Do not publish them, embed them in screenshots, or add them to an archive “for reproducibility.” Publish only disposable-lab PCAPNG evidence after reviewing its registration credentials and payload content.

## 7. `tshark` and `capinfos` examples

Run these on the evidence machine after setting `TRACE`, `KEYS`, and `RUN` to real paths.

**Container/capture metadata:**

```bash
capinfos "$TRACE"
sha256sum "$TRACE"
```

**Directional packet/byte table (secure example):**

```bash
tshark -r "$TRACE" -Y 'ip.addr == 10.0.1.10 && ip.addr == 10.0.3.10 && tcp.port == 8443' -T fields -E header=y -E separator=, -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.stream -e frame.len -e tcp.len
```

**TCP conversations and retransmission/duplicate-ACK review:**

```bash
tshark -r "$TRACE" -q -z conv,tcp
tshark -r "$TRACE" -Y 'tcp.analysis.retransmission || tcp.analysis.duplicate_ack' -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.stream -e tcp.seq -e tcp.ack -e tcp.len -e _ws.col.info
```

**TLS handshake versions and stream mapping:**

```bash
tshark -r "$TRACE" -Y 'tls.handshake' -T fields -E header=y -e frame.number -e tcp.stream -e ip.src -e ip.dst -e tls.handshake.type -e tls.handshake.version -e tls.handshake.extensions.supported_version
```

**Plaintext TCP payload hex for subsequent length/JSON/Base64 inspection:**

```bash
tshark -r "$TRACE" -Y 'tcp.port == 8080 && tcp.len > 0' -T fields -E header=y -e frame.number -e tcp.stream -e ip.src -e ip.dst -e tcp.payload
```

**Follow a selected plaintext TCP stream** (set `STREAM` from the packet table first):

```bash
STREAM=0
tshark -r "$TRACE" -q -z "follow,tcp,ascii,$STREAM"
```

**TLS decode with the test-only key log:**

```bash
tshark -r "$TRACE" -o "tls.keylog_file:$KEYS" -Y 'tls.handshake || tls.record.content_type == 23' -V
```

Inspect the verbose output for decrypted application data and the dissector path used by the installed Wireshark version. Do not treat the presence of `tls.app_data` alone as proof that the outer JSON was decoded. Use Wireshark's stream view for the final annotated screenshot when necessary.

Save command output alongside the curated screenshot only after reviewing it for secrets. Record the exact `tshark --version`, command, capture hash, and stream in the evidence notes.

## 8. Required annotated screenshot checklist

All routed entries below are **Pending privileged lab run**. Suggested filenames are organizational, not existing evidence.

| Suggested file | Required visible evidence and annotations | Status |
|---|---|---|
| `docs/evidence/01-topology-addressing.png` | Four namespaces, all interface IPs, static routes; label all three subnets. | Pending privileged lab run |
| `docs/evidence/02-traceroute-client-server.png` | Both R1/R2 hops and destination; command and actual addresses visible. | Pending privileged lab run |
| `docs/evidence/03-traceroute-server-client.png` | Reverse R2/R1 path; command and actual addresses visible. | Pending privileged lab run |
| `docs/evidence/04-netem-and-ping.png` | Both directional egress qdiscs, target `D`, bidirectional measured ping averages, RTT block. | Pending privileged lab run |
| `docs/evidence/10-plaintext-stream.png` | Port 8080, length-prefixed JSON, registration/send/deliver, Base64 payload explanation, frame/stream IDs. | Pending privileged lab run |
| `docs/evidence/20-tls13-handshake.png` | Port 8443, ClientHello/ServerHello, TLS 1.3 supported version, local-CA certificate, no key log. | Pending privileged lab run |
| `docs/evidence/21-tls-opaque-records.png` | Encrypted application records without key log; no readable room/chat JSON. | Pending privileged lab run |
| `docs/evidence/22-tls-keylog-decoded.png` | Same identified session with key log; registration/send/deliver visible; explicit “test key log used” label. | Pending privileged lab run |
| `docs/evidence/30-e2e-fingerprint-verification.png` | Own and peer full fingerprints, independent comparison context, explicit `/verify`/GUI verification, successful message. | Pending privileged lab run |
| `docs/evidence/31-e2e-keylog-ciphertext.png` | Decoded outer TLS showing only E2E nonce/ciphertext/metadata, no inner plaintext; keylog state labeled. | Pending privileged lab run |
| `docs/evidence/32-e2e-no-keylog.png` | Routed encrypted records and traffic metadata without key log. | Pending privileged lab run |
| `docs/evidence/40-full-suite-summary.png` | Manifest 81/81, all 27 conditions, three runs each, no failures; actual CSV/terminal context. | Pending privileged lab run |
| `docs/evidence/41-results-plots.png` | New setup, latency, CPU/wire plots with units and three-run spread; exact suite named in caption. | Pending privileged lab run |

For every annotation include mode, configured and measured RTT, payload size, run number, suite path, capture filename/hash, packet or stream identifiers, and whether key logging was active. Arrows/callouts must point to real output. Do not fabricate packet fields, blur contradictory evidence, or crop away the source/destination context.

## 9. Final integrity and publication review

1. Confirm `manifest.json` describes the full lab matrix—not the three-condition smoke matrix—and reports 81 successful runs with no failed/running runs.
2. Check every condition has three successful `run.json` files and exactly 1000 valid latency rows per run.
3. Check every required capture exists, opens as PCAPNG, corresponds to the correct run, and has non-null wire statistics. Disclose any exception rather than silently dropping it.
4. Cross-check reported numbers against `summary.csv` and raw run files; retain sample SD and within-run latency percentiles.
5. Verify topology summaries and measured ping values for all three RTTs and retain both traceroute directions.
6. Link every figure to a raw capture/result and record its SHA-256 hash. Keep smoke figures in a separately labeled appendix if included at all.
7. Exclude all root-level legacy keys/captures/`wire_results.txt` from the evidence bundle. Exclude every `*.key`, `*.keys`, `sslkeylog.txt`, `user_data/`, CA serial state, and unreviewed result directory.
8. Review PCAPNG and screenshots for credentials/content before publication. Use only disposable lab identities and passwords, and never describe redaction or TLS key logging as normal production behavior.
