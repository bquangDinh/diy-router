# cleanup old run
for ns in pc1 r1 r2 pc2; do
  sudo ip netns del "$ns" 2>/dev/null || true
done