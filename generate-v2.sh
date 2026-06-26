#!/usr/bin/env bash
set -e

# cleanup old run
for ns in pc1 r1 r2 pc2; do
  sudo ip netns del "$ns" 2>/dev/null || true
done

# create namespaces
for ns in pc1 r1 r2 pc2; do
  sudo ip netns add "$ns"
  sudo ip -n "$ns" link set lo up
done

# create links
sudo ip link add pc1-eth0 type veth peer name r1-eth0
sudo ip link add r1-eth1 type veth peer name r2-eth0
sudo ip link add r2-eth1 type veth peer name pc2-eth0

# move links into namespaces
sudo ip link set pc1-eth0 netns pc1
sudo ip link set r1-eth0 netns r1
sudo ip link set r1-eth1 netns r1
sudo ip link set r2-eth0 netns r2
sudo ip link set r2-eth1 netns r2
sudo ip link set pc2-eth0 netns pc2

# assign IPs
sudo ip -n pc1 addr add 10.0.1.2/24 dev pc1-eth0
sudo ip -n r1  addr add 10.0.1.1/24 dev r1-eth0

sudo ip -n r1  addr add 10.0.12.1/24 dev r1-eth1
sudo ip -n r2  addr add 10.0.12.2/24 dev r2-eth0

sudo ip -n r2  addr add 10.0.2.1/24 dev r2-eth1
sudo ip -n pc2 addr add 10.0.2.2/24 dev pc2-eth0

# bring interfaces up
for ns in pc1 r1 r2 pc2; do
  sudo ip -n "$ns" link set lo up
done

sudo ip -n pc1 link set pc1-eth0 up
sudo ip -n r1  link set r1-eth0 up
sudo ip -n r1  link set r1-eth1 up
sudo ip -n r2  link set r2-eth0 up
sudo ip -n r2  link set r2-eth1 up
sudo ip -n pc2 link set pc2-eth0 up

# enable forwarding on routers
sudo ip netns exec r1 sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo ip netns exec r2 sysctl -w net.ipv4.ip_forward=1 >/dev/null

# routes
sudo ip -n pc1 route add default via 10.0.1.1
sudo ip -n pc2 route add default via 10.0.2.1

sudo ip -n r1 route add 10.0.2.0/24 via 10.0.12.2 dev r1-eth1
sudo ip -n r2 route add 10.0.1.0/24 via 10.0.12.1 dev r2-eth0

echo "Done."
echo
echo "Test:"
echo "  sudo ip netns exec pc1 ping 10.0.2.2"
echo
echo "Watch ARP/ICMP on r1:"
echo "  sudo ip netns exec r1 tcpdump -i r1-eth0 -enn"
echo "  sudo ip netns exec r1 tcpdump -i r1-eth1 -enn"

read -p "Open 4 namespace terminals on second monitor? [y/N] " ans
[[ "$ans" =~ ^[Yy]$ ]] || exit 0

sudo -v

# Change this to match your second monitor position.
# Common setup: primary monitor 1920x1080 on the left,
# second monitor starts at X=1920.
MON_X=1920
MON_Y=99
MON_W=1920
MON_H=1080

CELL_W=$((MON_W / 2))
CELL_H=$((MON_H / 2))

open_ns() {
    local ns="$1"
    local x="$2"
    local y="$3"
    local w="$4"
    local h="$5"

    gnome-terminal --title="$ns" -- bash -c "sudo ip netns exec $ns bash" &

    sleep 1

    win_id=$(xdotool search --name "$ns" | tail -n 1 || true)

    if [ -z "$win_id" ]; then
        echo "Could not find window for $ns"
        return 1
    fi

    wmctrl -ir "$win_id" -b remove,maximized_vert,maximized_horz
    wmctrl -ir "$win_id" -e "0,$x,$y,$w,$h"
}

open_ns "pc1" "$MON_X"              "$MON_Y"              "$CELL_W" "$CELL_H"
open_ns "r1"  "$((MON_X+CELL_W))"   "$MON_Y"              "$CELL_W" "$CELL_H"
open_ns "r2"  "$MON_X"              "$((MON_Y+CELL_H))"   "$CELL_W" "$CELL_H"
open_ns "pc2" "$((MON_X+CELL_W))"   "$((MON_Y+CELL_H))"   "$CELL_W" "$CELL_H"