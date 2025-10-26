#!/usr/bin/env bash
set -euo pipefail

IF_IN=vf0_3
IF_OUT=vf0_1
PCAP=~/epifanio_proygrado/traffic-generator/traces/generated_int.pcap
RATE=10000   # target Mbps for tcpreplay

# --- Capture start counters ---
in_before=$(< /sys/class/net/$IF_IN/statistics/tx_packets)
out_before=$(< /sys/class/net/$IF_OUT/statistics/rx_packets)

# --- Run tcpreplay ---
echo "Running tcpreplay at ${RATE} Mbps on ${IF_IN}..."
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
