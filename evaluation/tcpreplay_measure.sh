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

# --- Configuration ---
IF_IN="vf0_3"
IF_OUT="vf0_1"
CAP_IN="/tmp/in_capture_$(date +%H%M%S).pcap"
CAP_OUT="/tmp/out_capture_$(date +%H%M%S).pcap"
CAPTURE_DURATION=15   # seconds, slightly longer than tcpreplay timeout
TCPREPLAY_TIMEOUT=12  # seconds

# --- Start tcpdump captures ---
echo "[INFO] Starting tcpdump on $IF_IN and $IF_OUT ..."
sudo timeout --preserve-status --signal SIGINT "${CAPTURE_DURATION}s" \
  tcpdump -n -i "$IF_IN" -B 2097151 -w "$CAP_IN" >/dev/null 2>&1 &
TCPDUMP_IN_PID=$!

sudo timeout --preserve-status --signal SIGINT "${CAPTURE_DURATION}s" \
  tcpdump -n -i "$IF_OUT" -B 2097151 -w "$CAP_OUT" >/dev/null 2>&1 &
TCPDUMP_OUT_PID=$!

sleep 2  # give tcpdump time to initialize

# --- Capture initial counters ---
in_before=$(< /sys/class/net/$IF_IN/statistics/tx_packets)
out_before=$(< /sys/class/net/$IF_OUT/statistics/rx_packets)

# --- Run tcpreplay ---
echo "[INFO] Running tcpreplay on ${IF_IN} ..."
sudo timeout "${TCPREPLAY_TIMEOUT}" tcpreplay --preload-pcap --loop=5 -i "$IF_IN" --topspeed "$PCAP" | tee tcpreplay.log

# --- Capture final counters ---
in_after=$(< /sys/class/net/$IF_IN/statistics/tx_packets)
out_after=$(< /sys/class/net/$IF_OUT/statistics/rx_packets)

# --- Stop tcpdump ---
echo "[INFO] Stopping tcpdump captures ..."
sudo kill -SIGINT "$TCPDUMP_IN_PID" "$TCPDUMP_OUT_PID" 2>/dev/null || true
sleep 2  # allow tcpdump to flush files

# --- Compute durations using capinfos ---
get_duration() {
  local file="$1"
  if [[ -f "$file" ]]; then
    local dur
    dur=$(capinfos -a -M "$file" 2>/dev/null | awk -F': ' '/Capture duration/ {print $2}' | awk '{print $1}')
    [[ -n "$dur" ]] && echo "$dur" || echo "0"
  else
    echo "0"
  fi
}

elapsed_in=$(get_duration "$CAP_IN")
elapsed_out=$(get_duration "$CAP_OUT")

# --- Compute stats ---
delta_in=$((in_after - in_before))
delta_out=$((out_after - out_before))
pps_in=$(awk -v n="$delta_in" -v d="$elapsed_in" 'BEGIN {if (d>0) printf "%.2f", n/d; else print 0}')
pps_out=$(awk -v n="$delta_out" -v d="$elapsed_out" 'BEGIN {if (d>0) printf "%.2f", n/d; else print 0}')
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
