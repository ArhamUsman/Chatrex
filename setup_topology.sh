#!/bin/bash
set -euo pipefail
export LC_ALL=C

# Network setup only: the server namespace is ready for the lab application on
# 10.0.3.10 (secure TLS on TCP/8443 and intentionally insecure plaintext on
# TCP/8080). The application lifecycle is intentionally managed separately.

namespaces=(client r1 r2 server)
setup_complete=false

usage() {
    printf 'Usage: %s [RTT_MS] [LOSS_PERCENT] [JITTER_MS]\n' "$0" >&2
    printf 'Defaults: RTT_MS=20 LOSS_PERCENT=0 JITTER_MS=0\n' >&2
}

require_root() {
    if (( EUID != 0 )); then
        printf 'Error: this script must run as root; invoke it with sudo.\n' >&2
        exit 1
    fi
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

is_zero() {
    awk -v value="$1" 'BEGIN { exit (value == 0) ? 0 : 1 }'
}

namespace_exists() {
    local wanted=$1
    ip netns list | awk -v wanted="$wanted" '$1 == wanted { found=1 } END { exit !found }'
}

delete_namespace_if_present() {
    local namespace=$1
    if namespace_exists "$namespace"; then
        ip netns del "$namespace"
    fi
}

cleanup_on_exit() {
    if [[ $setup_complete != true ]]; then
        printf '\n[!] Setup did not complete; removing partial lab namespaces.\n' >&2
        local namespace
        for namespace in "${namespaces[@]}"; do
            if namespace_exists "$namespace"; then
                ip netns del "$namespace" 2>/dev/null || true
            fi
        done
    fi
}

apply_netem() {
    local namespace=$1
    local interface=$2
    local -a tc_args=(qdisc replace dev "$interface" root netem delay "${one_way_delay}ms")

    if ! is_zero "$jitter_input"; then
        tc_args+=("${jitter_value}ms")
    fi
    if ! is_zero "$loss_input"; then
        tc_args+=(loss "${loss_value}%")
    fi

    ip netns exec "$namespace" tc "${tc_args[@]}"
}

verify_qdisc() {
    local namespace=$1
    local interface=$2
    local output

    output=$(ip netns exec "$namespace" tc qdisc show dev "$interface")
    printf '%s\n' "$output"
    if [[ $output != *netem* ]]; then
        printf 'Error: netem qdisc is missing on %s/%s.\n' "$namespace" "$interface" >&2
        return 1
    fi
}

if (( $# > 3 )); then
    usage
    exit 2
fi

rtt_input=${1:-20}
loss_input=${2:-0}
jitter_input=${3:-0}

if ! is_nonnegative_decimal "$rtt_input"; then
    printf 'Error: RTT_MS must be a non-negative decimal number.\n' >&2
    exit 2
fi
if ! is_nonnegative_decimal "$loss_input"; then
    printf 'Error: LOSS_PERCENT must be a non-negative decimal number.\n' >&2
    exit 2
fi
if ! awk -v loss="$loss_input" 'BEGIN { exit (loss <= 100) ? 0 : 1 }'; then
    printf 'Error: LOSS_PERCENT must not exceed 100.\n' >&2
    exit 2
fi
if ! is_nonnegative_decimal "$jitter_input"; then
    printf 'Error: JITTER_MS must be a non-negative decimal number.\n' >&2
    exit 2
fi

require_root
for required_command in ip awk tc sysctl ping traceroute; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'Error: required command not found: %s\n' "$required_command" >&2
        exit 1
    fi
done

rtt_value=$(format_decimal "$rtt_input")
loss_value=$(format_decimal "$loss_input")
jitter_value=$(format_decimal "$jitter_input")
one_way_delay=$(format_decimal "$(awk -v rtt="$rtt_input" 'BEGIN { print rtt / 2 }')")

trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '[*] Removing only existing lab namespaces, if present.\n'
for namespace in "${namespaces[@]}"; do
    delete_namespace_if_present "$namespace"
done

printf '[*] Creating network namespaces: client, r1, r2, server.\n'
for namespace in "${namespaces[@]}"; do
    ip netns add "$namespace"
done

printf '[*] Creating and attaching veth pairs.\n'
ip link add veth-client type veth peer name veth-r1-a
ip link add veth-r1-b type veth peer name veth-r2-b
ip link add veth-r2-c type veth peer name veth-server

ip link set veth-client netns client
ip link set veth-r1-a netns r1
ip link set veth-r1-b netns r1
ip link set veth-r2-b netns r2
ip link set veth-r2-c netns r2
ip link set veth-server netns server

printf '[*] Configuring interfaces and loopbacks.\n'
ip netns exec client ip addr add 10.0.1.10/24 dev veth-client
ip netns exec client ip link set veth-client up

ip netns exec r1 ip addr add 10.0.1.1/24 dev veth-r1-a
ip netns exec r1 ip addr add 10.0.2.1/24 dev veth-r1-b
ip netns exec r1 ip link set veth-r1-a up
ip netns exec r1 ip link set veth-r1-b up

ip netns exec r2 ip addr add 10.0.2.2/24 dev veth-r2-b
ip netns exec r2 ip addr add 10.0.3.1/24 dev veth-r2-c
ip netns exec r2 ip link set veth-r2-b up
ip netns exec r2 ip link set veth-r2-c up

ip netns exec server ip addr add 10.0.3.10/24 dev veth-server
ip netns exec server ip link set veth-server up

for namespace in "${namespaces[@]}"; do
    ip netns exec "$namespace" ip link set lo up
done

printf '[*] Enabling forwarding on r1 and r2.\n'
ip netns exec r1 sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec r2 sysctl -w net.ipv4.ip_forward=1 >/dev/null

printf '[*] Installing static routes.\n'
ip netns exec client ip route add default via 10.0.1.1
ip netns exec server ip route add default via 10.0.3.1
ip netns exec r1 ip route add 10.0.3.0/24 via 10.0.2.2
ip netns exec r2 ip route add 10.0.1.0/24 via 10.0.2.1

# netem delay is an egress delay, not a round-trip delay on each interface.
# A client request crosses r1/veth-r1-b once and waits D; its reply crosses
# r2/veth-r2-b once and waits D. Setting D=RTT/2 on both interfaces therefore
# adds D+D=RTT to the otherwise-unimpaired end-to-end round trip.
printf '[*] Applying target added RTT %s ms as %s ms on each inter-router egress.\n' \
    "$rtt_value" "$one_way_delay"
apply_netem r1 veth-r1-b
apply_netem r2 veth-r2-b

printf '[*] Verifying installed netem qdiscs.\n'
verify_qdisc r1 veth-r1-b
verify_qdisc r2 veth-r2-b

printf '[*] Verifying bidirectional connectivity with ping.\n'
ip netns exec client ping -n -c 3 -W 2 10.0.3.10
ip netns exec server ping -n -c 3 -W 2 10.0.1.10

printf '[*] Verifying bidirectional routes with traceroute.\n'
ip netns exec client traceroute -n -w 1 -q 1 10.0.3.10
ip netns exec server traceroute -n -w 1 -q 1 10.0.1.10

setup_complete=true
printf '[+] Topology setup and verification completed successfully.\n'
printf '    Target added RTT: %s ms; per-egress delay: %s ms; per-egress loss: %s%%; jitter: %s ms.\n' \
    "$rtt_value" "$one_way_delay" "$loss_value" "$jitter_value"
