#!/bin/bash

gnome-terminal --title="pc1" -- bash -c "ip netns exec pc1 bash; exec bash"
gnome-terminal --title="pc2" -- bash -c "ip netns exec pc2 bash; exec bash"
gnome-terminal --title="r1"  -- bash -c "ip netns exec r1 bash; exec bash"
gnome-terminal --title="r2"  -- bash -c "ip netns exec r2 bash; exec bash"