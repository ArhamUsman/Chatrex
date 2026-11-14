#!/bin/bash
set -euo pipefail
export LC_ALL=C

namespaces=(client r1 r2 server)
overall_pass=true
failures=()

usage() {
    printf 'Usage: %s [OUTPUT_DIR]\n' "$0" >&2
    printf 'Default OUTPUT_DIR: results/topology\n' >&2
    printf 'Set EXPECTED_RTT_MS to check measured ping averages against a target.\n' >&2
}

namespace_exists() {
    local wanted=$1
    ip netns list | awk -v wanted="$wanted" '$1 == wanted { found=1 } END { exit !found }'
}

is_nonnegative_decimal() {
    [[ $1 =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]]
}

format_decimal() {
    awk -v value="$1" 'BEGIN {
        text = sprintf("%.10f", value)
        sub(/0+$/, "", text)
        sub(/[.]$/, "", text)
        if (text == "" || text == "-0") text = "0"
        print text
    }'
}

capture_evidence() {
    local file=$1
    shift

    if "$@" >"$file" 2>&1; then
        printf '[+] Saved %s\n' "$file"
    else
        local status=$?
        printf '\n[validation: command exited with status %d]\n' "$status" >>"$file"
        printf '[!] Command failed (status %d); evidence saved in %s\n' "$status" "$file" >&2
        failures+=("${file##*/}: command exited with status $status")
        overall_pass=false
    fi
}

parse_ping_average() {
    awk '
        /^(rtt|round-trip)[[:space:]]/ {
            stats = $0
            sub(/^[^=]*=[[:space:]]*/, "", stats)
            count = split(stats, parts, "/")
            if (count >= 2) {
                candidate = parts[2]
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
                if (candidate ~ /^[0-9]+([.][0-9]+)?$/) {
                    print candidate
                    found = 1
                    exit
                }
            }
        }
        END { if (!found) exit 1 }
    ' "$1"
}

rtt_within_tolerance() {
    awk -v measured="$1" -v expected="$2" -v tolerance="$3" 'BEGIN {
        difference = measured - expected
        if (difference < 0) difference = -difference
        exit (difference <= tolerance) ? 0 : 1
    }'
}

if (( $# > 1 )); then
    usage
    exit 2
fi

output_dir=${1:-results/topology}
expected_rtt=${EXPECTED_RTT_MS-}

if [[ -n $expected_rtt ]] && ! is_nonnegative_decimal "$expected_rtt"; then
    printf 'Error: EXPECTED_RTT_MS must be a non-negative decimal number.\n' >&2
    exit 2
fi

if (( EUID != 0 )); then
    printf 'Error: this script must run as root; invoke it with sudo.\n' >&2
    exit 1
fi

for required_command in ip awk ping traceroute tc; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$required_command" >&2
        exit 1
    fi
done

missing_namespaces=()
for namespace in "${namespaces[@]}"; do
    if ! namespace_exists "$namespace"; then
        missing_namespaces+=("$namespace")
    fi
done
if (( ${#missing_namespaces[@]} > 0 )); then
    printf 'Error: lab is incomplete; missing namespace(s): %s\n' "${missing_namespaces[*]}" >&2
    exit 1
fi

mkdir -p -- "$output_dir"

for namespace in "${namespaces[@]}"; do
    capture_evidence "$output_dir/${namespace}_ip_addr.txt" \
        ip netns exec "$namespace" ip addr show
    capture_evidence "$output_dir/${namespace}_ip_route.txt" \
        ip netns exec "$namespace" ip route show
done

capture_evidence "$output_dir/route_get_client_to_server.txt" \
    ip netns exec client ip route get 10.0.3.10
capture_evidence "$output_dir/route_get_server_to_client.txt" \
    ip netns exec server ip route get 10.0.1.10

ping_client_file="$output_dir/ping_client_to_server.txt"
ping_server_file="$output_dir/ping_server_to_client.txt"
capture_evidence "$ping_client_file" \
    ip netns exec client ping -n -c 5 -W 2 10.0.3.10
capture_evidence "$ping_server_file" \
    ip netns exec server ping -n -c 5 -W 2 10.0.1.10

capture_evidence "$output_dir/traceroute_client_to_server.txt" \
    ip netns exec client traceroute -n -w 1 -q 1 10.0.3.10
capture_evidence "$output_dir/traceroute_server_to_client.txt" \
    ip netns exec server traceroute -n -w 1 -q 1 10.0.1.10

tc_r1_file="$output_dir/tc_r1_veth-r1-b.txt"
tc_r2_file="$output_dir/tc_r2_veth-r2-b.txt"
capture_evidence "$tc_r1_file" \
    ip netns exec r1 tc -s qdisc show dev veth-r1-b
capture_evidence "$tc_r2_file" \
    ip netns exec r2 tc -s qdisc show dev veth-r2-b

for tc_file in "$tc_r1_file" "$tc_r2_file"; do
    if [[ $(<"$tc_file") != *netem* ]]; then
        printf '[!] No netem qdisc found in %s\n' "$tc_file" >&2
        failures+=("${tc_file##*/}: netem qdisc missing")
        overall_pass=false
    fi
done

client_average=
server_average=
if client_average=$(parse_ping_average "$ping_client_file"); then
    client_average_display="$client_average ms"
else
    client_average_display=unavailable
    failures+=("ping_client_to_server.txt: average RTT unavailable")
    overall_pass=false
fi
if server_average=$(parse_ping_average "$ping_server_file"); then
    server_average_display="$server_average ms"
else
    server_average_display=unavailable
    failures+=("ping_server_to_client.txt: average RTT unavailable")
    overall_pass=false
fi

client_target_check='not checked'
server_target_check='not checked'
expected_display='not checked (EXPECTED_RTT_MS is not set)'
tolerance_display=not_checked
if [[ -n $expected_rtt ]]; then
    expected_value=$(format_decimal "$expected_rtt")
    tolerance=$(awk -v expected="$expected_rtt" 'BEGIN {
        value = expected * 0.05
        if (value < 1) value = 1
        print value
    }')
    tolerance_value=$(format_decimal "$tolerance")
    expected_display="$expected_value ms"
    tolerance_display="+/- $tolerance_value ms (maximum of 1 ms and 5%)"

    if [[ -n $client_average ]] && rtt_within_tolerance "$client_average" "$expected_rtt" "$tolerance"; then
        client_target_check=PASS
    else
        client_target_check=FAIL
        failures+=("client-to-server measured average RTT is unavailable or outside tolerance")
        overall_pass=false
    fi

    if [[ -n $server_average ]] && rtt_within_tolerance "$server_average" "$expected_rtt" "$tolerance"; then
        server_target_check=PASS
    else
        server_target_check=FAIL
        failures+=("server-to-client measured average RTT is unavailable or outside tolerance")
        overall_pass=false
    fi
fi

result=FAIL
if [[ $overall_pass == true ]]; then
    result=PASS
fi

summary_file="$output_dir/topology_summary.txt"
{
    printf 'Topology validation: %s\n' "$result"
    printf 'Measured ping average RTT (client -> server): %s\n' "$client_average_display"
    printf 'Measured ping average RTT (server -> client): %s\n' "$server_average_display"
    printf 'Expected average RTT: %s\n' "$expected_display"
    printf 'RTT tolerance: %s\n' "$tolerance_display"
    printf 'Client -> server target check: %s\n' "$client_target_check"
    printf 'Server -> client target check: %s\n' "$server_target_check"
    printf 'Note: ping reports measured averages including baseline path latency, not exact configured netem delay.\n'
    if (( ${#failures[@]} > 0 )); then
        printf 'Failures:\n'
        for failure in "${failures[@]}"; do
            printf '  - %s\n' "$failure"
        done
    fi
} >"$summary_file"

printf '[*] Validation summary:\n'
cat "$summary_file"

if [[ $overall_pass == true ]]; then
    exit 0
fi
exit 1
