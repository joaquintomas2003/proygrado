#!/usr/bin/env bash
set -euo pipefail

# --- Arguments ---
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <pcap_file>"
  exit 1
fi

PCAP="$1"

if [[ ! -f "$PCAP" ]]; then
  echo "Error: file '$PCAP' not found."
  exit 1
fi

# --- Fixed parameters ---
IF_IN=vf0_3
IF_OUT=vf0_1

# --- Capture start counters ---
in_before=$(< /sys/class/net/$IF_IN/statistics/tx_packets)
out_before=$(< /sys/class/net/$IF_OUT/statistics/rx_packets)

# --- Run tcpreplay ---
echo "Running tcpreplay at top-speed on ${IF_IN}..."
sudo timeout 12 tcpreplay --preload-pcap --loop=5 -i "$IF_IN" --topspeed "$PCAP" | tee tcpreplay.log

read duration < <(awk '/^Actual:/ {print $8}' tcpreplay.log)

# --- Capture end counters ---
in_after=$(< /sys/class/net/$IF_IN/statistics/tx_packets)
out_after=$(< /sys/class/net/$IF_OUT/statistics/rx_packets)

# --- Compute elapsed time and stats ---
elapsed=$duration
delta_in=$((in_after - in_before))
delta_out=$((out_after - out_before))
pps_in=$(awk -v n="$delta_in" -v d="$elapsed" 'BEGIN {printf "%.8f", n / d}')
pps_out=$(awk -v n="$delta_out" -v d="$elapsed" 'BEGIN {printf "%.8f", n / d}')
loss_pct=$(awk "BEGIN { if ($delta_in > 0) print (1 - $delta_out / $delta_in) * 100; else print 0 }")

# --- Print results ---
echo ""
echo "===== Throughput Results ====="
printf "Duration          : %.3f seconds\n" "$elapsed"
printf "Ingress packets   : %'d\n" "$delta_in"
printf "Egress packets    : %'d\n" "$delta_out"
printf "Ingress rate      : %.2f pps\n" "$pps_in"
printf "Egress rate       : %.2f pps\n" "$pps_out"
printf "Packet loss       : %.2f %%\n" "$loss_pct"
echo "=============================="
