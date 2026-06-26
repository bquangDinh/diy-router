#!/usr/bin/env bash
set -e

# clean old setup if it exists
sudo ip netns del pc1 2>/dev/null || true
sudo ip netns del r1  2>/dev/null || true
sudo ip netns del pc2 2>/dev/null || true

# create namespaces
sudo ip netns add pc1
sudo ip netns add r1
sudo ip netns add pc2

# create veth cables
sudo ip link add pc1-eth0 type veth peer name r1-eth0
sudo ip link add pc2-eth0 type veth peer name r1-eth1

# move interfaces into namespaces
sudo ip link set pc1-eth0 netns pc1
sudo ip link set r1-eth0 netns r1

sudo ip link set pc2-eth0 netns pc2
sudo ip link set r1-eth1 netns r1

# assign IPs
sudo ip netns exec pc1 ip addr add 10.0.1.2/24 dev pc1-eth0
sudo ip netns exec r1  ip addr add 10.0.1.1/24 dev r1-eth0

sudo ip netns exec pc2 ip addr add 10.0.2.2/24 dev pc2-eth0
sudo ip netns exec r1  ip addr add 10.0.2.1/24 dev r1-eth1

# bring loopback up
sudo ip netns exec pc1 ip link set lo up
sudo ip netns exec r1  ip link set lo up
sudo ip netns exec pc2 ip link set lo up

# bring interfaces up
sudo ip netns exec pc1 ip link set pc1-eth0 up
sudo ip netns exec r1  ip link set r1-eth0 up

sudo ip netns exec pc2 ip link set pc2-eth0 up
sudo ip netns exec r1  ip link set r1-eth1 up

# enable routing inside router namespace
sudo ip netns exec r1 sysctl -w net.ipv4.ip_forward=1 >/dev/null

# add default routes for PCs
sudo ip netns exec pc1 ip route add default via 10.0.1.1
sudo ip netns exec pc2 ip route add default via 10.0.2.1

echo "Done."
echo
echo "Test:"
echo "  sudo ip netns exec pc1 ping 10.0.2.2"
echo
echo "Inspect routes:"
echo "  sudo ip netns exec pc1 ip route"
echo "  sudo ip netns exec r1 ip route"
echo "  sudo ip netns exec pc2 ip route"