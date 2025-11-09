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
CAP_IN=/tmp/in_capture.pcap
CAP_OUT=/tmp/out_capture.pcap

# --- Cleanup handler ---
cleanup() {
  echo "Stopping tcpdump captures..."
  pkill -P $$ tcpdump || true
}
trap cleanup EXIT

# --- Start captures ---
echo "Starting tcpdump on $IF_IN and $IF_OUT..."
sudo tcpdump -i "$IF_IN" -w "$CAP_IN" >/dev/null 2>&1 &
sudo tcpdump -i "$IF_OUT" -w "$CAP_OUT" >/dev/null 2>&1 &
sleep 1

# --- Record initial counters ---
in_before=$(< /sys/class/net/$IF_IN/statistics/tx_packets)
out_before=$(< /sys/class/net/$IF_OUT/statistics/rx_packets)

# --- Run tcpreplay ---
echo "Running tcpreplay at top-speed on ${IF_IN}..."
sudo timeout 12 tcpreplay --preload-pcap --loop=5 -i "$IF_IN" --topspeed "$PCAP" | tee tcpreplay.log

read duration < <(awk '/^Actual:/ {print $8}' tcpreplay.log)

# --- Record final counters ---
in_after=$(< /sys/class/net/$IF_IN/statistics/tx_packets)
out_after=$(< /sys/class/net/$IF_OUT/statistics/rx_packets)

# --- Kill tcpdump and wait ---
cleanup
sleep 1  # allow final packets to flush

# --- Compute elapsed time from captures ---
get_duration() {
  local file="$1"
  if [[ -f "$file" ]]; then
    local first_ts last_ts
    first_ts=$(tshark -r "$file" -T fields -e frame.time_epoch 2>/dev/null | head -n1)
    last_ts=$(tshark -r "$file" -T fields -e frame.time_epoch 2>/dev/null | tail -n1)
    if [[ -n "$first_ts" && -n "$last_ts" ]]; then
      awk -v a="$first_ts" -v b="$last_ts" 'BEGIN {printf "%.8f", b - a}'
      return
    fi
  fi
  echo "0"
}

elapsed_in=$(get_duration "$CAP_IN")
elapsed_out=$(get_duration "$CAP_OUT")

# --- Compute stats ---
delta_in=$((in_after - in_before))
delta_out=$((out_after - out_before))
pps_in=$(awk -v n="$delta_in" -v d="$elapsed_in" 'BEGIN { if (d>0) printf "%.2f", n / d; else print 0 }')
pps_out=$(awk -v n="$delta_out" -v d="$elapsed_out" 'BEGIN { if (d>0) printf "%.2f", n / d; else print 0 }')
loss_pct=$(awk "BEGIN { if ($delta_in > 0) print (1 - $delta_out / $delta_in) * 100; else print 0 }")

# --- Print results ---
echo ""
echo "===== Throughput Results ====="
printf "Ingress duration   : %.3f seconds\n" "$elapsed_in"
printf "Egress duration    : %.3f seconds\n" "$elapsed_out"
printf "Ingress packets    : %'d\n" "$delta_in"
printf "Egress packets     : %'d\n" "$delta_out"
printf "Ingress rate       : %.2f pps\n" "$pps_in"
printf "Egress rate        : %.2f pps\n" "$pps_out"
printf "Packet loss        : %.2f %%\n" "$loss_pct"
echo "=============================="
