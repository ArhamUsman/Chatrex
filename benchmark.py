import time
import socket
import ssl
import struct
import datetime
import subprocess
import re
import statistics
from nacl.public import PrivateKey, PublicKey, Box

def detect_network_rtt():
    """Automatically pings the server to measure and format the current network RTT."""
    print("[*] Probing network RTT via ping...")
    try:
        result = subprocess.run(
            ["ping", "-c", "3", "10.0.3.10"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)', result.stdout)
            if match:
                avg_rtt = float(match.group(1))
                detected_label = f"{round(avg_rtt)}ms RTT"
                print(f"[+] Detected Network RTT: {detected_label}")
                return detected_label
    except Exception as e:
        print(f"[-] Could not auto-detect RTT: {e}")
    
    return "Custom RTT"

def recv_exact(sock, num_bytes):
    data = bytearray()
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def single_run_benchmark(mode, size_bytes, num_messages=100):
    """Performs a single trial run and returns setup time and average message latency."""
    client_priv = PrivateKey.generate()
    client_pub = client_priv.public_key
    box = None

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    t_start_conn = time.perf_counter()
    try:
        raw_sock.connect(('10.0.3.10', 8443))

        if mode == "plaintext":
            raw_sock.sendall(b'\x00')
            client = raw_sock
        elif mode == "tls":
            raw_sock.sendall(b'\x01')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cafile="ca.crt")
            context.check_hostname = False
            client = context.wrap_socket(raw_sock, server_hostname="10.0.3.10")
        elif mode == "e2e":
            raw_sock.sendall(b'\x02')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(cafile="ca.crt")
            context.check_hostname = False
            client = context.wrap_socket(raw_sock, server_hostname="10.0.3.10")
            
            client.sendall(bytes(client_pub))
            server_pub_bytes = recv_exact(client, 32)
            if not server_pub_bytes or len(server_pub_bytes) != 32:
                raw_sock.close()
                return None, None
            
            server_pub = PublicKey(server_pub_bytes)
            box = Box(client_priv, server_pub)

    except Exception as e:
        return None, None
        
    t_conn_time = (time.perf_counter() - t_start_conn) * 1000

    payload = b"A" * size_bytes
    latencies = []

    for i in range(1, num_messages + 1):
        t0 = time.perf_counter()
        try:
            if mode == "e2e":
                ciphertext = box.encrypt(payload)
                length_header = struct.pack('!I', len(ciphertext))
                client.sendall(length_header + ciphertext)
            else:
                length_header = struct.pack('!I', len(payload))
                client.sendall(length_header + payload)
            
            raw_len = recv_exact(client, 4)
            if not raw_len:
                break
            msg_len = struct.unpack('!I', raw_len)[0]
            
            data = recv_exact(client, msg_len)
            if not data:
                break

            if mode == "e2e":
                box.decrypt(bytes(data))

        except Exception:
            break
            
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)

    client.close()
    
    if len(latencies) == num_messages:
        avg_latency = sum(latencies) / len(latencies)
        return t_conn_time, avg_latency
    else:
        return None, None

def run_benchmark_suite_for_condition(mode, size_bytes, net_delay_label, num_runs=3, num_messages=100):
    """Executes multiple runs and records individual trial times alongside mean and stdev."""
    print(f"\n[*] Benchmarking: Mode={mode.upper()}, Size={size_bytes}B, Target RTT={net_delay_label} ({num_runs} runs)...")
    setup_times = []
    avg_rtts = []

    for r in range(1, num_runs + 1):
        setup_t, avg_rtt = single_run_benchmark(mode, size_bytes, num_messages)
        if setup_t is not None and avg_rtt is not None:
            setup_times.append(setup_t)
            avg_rtts.append(avg_rtt)
        else:
            # Retry once if a run drops unexpectedly
            setup_t, avg_rtt = single_run_benchmark(mode, size_bytes, num_messages)
            if setup_t is not None and avg_rtt is not None:
                setup_times.append(setup_t)
                avg_rtts.append(avg_rtt)

    if len(setup_times) > 0:
        mean_setup = statistics.mean(setup_times)
        std_setup = statistics.stdev(setup_times) if len(setup_times) > 1 else 0.0
        
        mean_rtt = statistics.mean(avg_rtts)
        std_rtt = statistics.stdev(avg_rtts) if len(avg_rtts) > 1 else 0.0

        # Format individual runs nicely for output
        setup_runs_str = ", ".join([f"{t:.2f}ms" for t in setup_times])
        rtt_runs_str = ", ".join([f"{r:.2f}ms" for r in avg_rtts])

        result_str = (
            f"[RESULT] NetRTT: {net_delay_label} | Mode: {mode.upper()} | Size: {size_bytes}B\n"
            f"         -> Setup Times (Runs): [{setup_runs_str}] | Mean: {mean_setup:.2f}ms (±{std_setup:.2f})\n"
            f"         -> Avg RTTs (Runs):    [{rtt_runs_str}] | Mean: {mean_rtt:.2f}ms (±{std_rtt:.2f})"
        )
        print(result_str)
        return result_str
    else:
        print(f"[-] All runs failed for {mode} at {size_bytes}B.")
        return None

if __name__ == "__main__":
    print("=== AUTOMATED MULTI-RUN MULTI-MODE BENCHMARK SUITE ===")
    
    current_rtt_label = detect_network_rtt()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_lines = [
        "=" * 90,
        f" AUTOMATED BENCHMARK REPORT (Granular Run Data | RTT: {current_rtt_label})",
        f" Timestamp: {timestamp}",
        "=" * 90
    ]

    modes = ["plaintext", "tls", "e2e"]
    sizes = [64, 1024, 16384]

    for mode in modes:
        for size in sizes:
            res = run_benchmark_suite_for_condition(mode, size, net_delay_label=current_rtt_label, num_runs=3, num_messages=100)
            if res:
                report_lines.append(res)

    report_lines.append("=" * 90 + "\n")

    with open("benchmark_results.txt", "a") as f:
        f.write("\n".join(report_lines) + "\n")

    print("\n[*] Benchmark suite completed! Granular results saved to benchmark_results.txt.")