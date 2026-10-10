#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "[*] Cleaning up old namespaces if they exist..."
ip netns del client-ns 2>/dev/null || true
ip netns del r1-ns 2>/dev/null || true
ip netns del r2-ns 2>/dev/null || true
ip netns del server-ns 2>/dev/null || true

echo "[*] Creating network namespaces..."
ip netns add client-ns
ip netns add r1-ns
ip netns add r2-ns
ip netns add server-ns

echo "[*] Creating virtual Ethernet (veth) pairs for Subnets A, B, and C..."
# Subnet A: Client <--> R1
ip link add v-client-cli type veth peer name v-r1-a
ip link set v-client-cli netns client-ns
ip link set v-r1-a netns r1-ns

# Subnet B: R1 <--> R2 (Where netem delay will live)
ip link add v-r1-b type veth peer name v-r2-b
ip link set v-r1-b netns r1-ns
ip link set v-r2-b netns r2-ns

# Subnet C: R2 <--> Server
ip link add v-r2-c type veth peer name v-server-c
ip link set v-r2-c netns r2-ns
ip link set v-server-c netns server-ns

echo "[*] Assigning IP addresses..."
# Subnet A (10.0.1.0/24)
ip netns exec client-ns ip addr add 10.0.1.10/24 dev v-client-cli
ip netns exec r1-ns ip addr add 10.0.1.1/24 dev v-r1-a

# Subnet B (10.0.2.0/24)
ip netns exec r1-ns ip addr add 10.0.2.1/24 dev v-r1-b
ip netns exec r2-ns ip addr add 10.0.2.2/24 dev v-r2-b

# Subnet C (10.0.3.0/24)
ip netns exec r2-ns ip addr add 10.0.3.1/24 dev v-r2-c
ip netns exec server-ns ip addr add 10.0.3.10/24 dev v-server-c

echo "[*] Bringing up all network interfaces..."
ip netns exec client-ns ip link set lo up
ip netns exec client-ns ip link set v-client-cli up
ip netns exec r1-ns ip link set lo up
ip netns exec r1-ns ip link set v-r1-a up
ip netns exec r1-ns ip link set v-r1-b up
ip netns exec r2-ns ip link set lo up
ip netns exec r2-ns ip link set v-r2-b up
ip netns exec r2-ns ip link set v-r2-c up
ip netns exec server-ns ip link set lo up
ip netns exec server-ns ip link set v-server-c up

echo "[*] Enabling IP forwarding on routers R1 and R2..."
ip netns exec r1-ns sysctl -w net.ipv4.ip_forward=1 > /dev/null
ip netns exec r2-ns sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo "[*] Configuring static routing tables..."
# Client route to Subnet C via R1
ip netns exec client-ns ip route add 10.0.3.0/24 via 10.0.1.1 dev v-client-cli

# R1 route to Subnet C via R2
ip netns exec r1-ns ip route add 10.0.3.0/24 via 10.0.2.2 dev v-r1-b

# R2 route to Subnet A via R1
ip netns exec r2-ns ip route add 10.0.1.0/24 via 10.0.2.1 dev v-r2-b

# Server route back to Subnet A via R2
ip netns exec server-ns ip route add 10.0.1.0/24 via 10.0.3.1 dev v-server-c

echo "[*] Applying network impairments (tc netem) on Subnet B link (e.g., 20ms RTT)..."
ip netns exec r1-ns tc qdisc add dev v-r1-b root netem delay 10ms

echo "[+] Multi-subnet routed topology successfully created!"
echo "    - Client: 10.0.1.10"
echo "    - Relay Server: 10.0.3.10:8443"
echo "    - Routers: R1 (10.0.1.1 / 10.0.2.1), R2 (10.0.2.2 / 10.0.3.1)"