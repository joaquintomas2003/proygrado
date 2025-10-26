#!/usr/bin/env bash
set -euo pipefail

# CONFIGURATION
IFACE_RX="vf0_1"                              # receiver interface (kernel-bound)
PCAP_OUT_NAME="capture_$(date +%H%M%S).pcap"  # unique filename in RAM disk
PCAP_OUT_PATH="/mnt/ramdisk/$PCAP_OUT_NAME"

# TRACE TO REPLAY
TRACE_PATH="$HOME/epifanio_proygrado/traffic-generator/traces/generated_int.pcap"
REPLAY_SCRIPT="evaluation/replay_pcap.lua"
DEV_TX=0                                      # MoonGen device id
ITERATIONS=100                                # how many times to replay

# ---- 1. Start tcpdump capture ----
echo "[INFO] Starting tcpdump capture on $IFACE_RX ..."
sudo timeout --preserve-status --signal SIGINT 20s \
  tcpdump -n udp -i "$IFACE_RX" -B 2097151 -w "$PCAP_OUT_PATH" &
TCPDUMP_PID=$!
sleep 2                                       # give tcpdump a moment to start

# ---- 2. Run MoonGen ----
echo "[INFO] Running MoonGen replay ..."
sudo MoonGen "$REPLAY_SCRIPT" "$DEV_TX" "$TRACE_PATH" -n "$ITERATIONS" | tee moongen_output.log

# ---- 3. Stop tcpdump ----
echo "[INFO] Stopping tcpdump (pid=$TCPDUMP_PID) ..."
sudo kill -SIGINT "$TCPDUMP_PID"
sleep 2

# ---- 4. Move capture file ----
echo "[INFO] Moving capture to current directory ..."
sudo mv "$PCAP_OUT_PATH" .

# ---- 5. Run capinfos ----
echo "[INFO] Extracting capture info ..."
CAPINFOS_OUTPUT=$(capinfos "$PCAP_OUT_NAME")

# Print capture summary
echo "================ CAPTURE SUMMARY ================"
echo "$CAPINFOS_OUTPUT" | grep -E 'Number of packets:|Data size:|Capture duration:|Data bit rate:|Average packet rate:'
echo "================================================="

# ---- 6. Compare PPS between sender and receiver ----
echo "[INFO] Comparing sender vs receiver rates ..."

# Remove any color escape codes from MoonGen output before parsing
MOONGEN_CLEAN=$(sed 's/\x1b\[[0-9;]*m//g' moongen_output.log)

# Extract Mpps and Mbps from MoonGen
MOONGEN_MPPS=$(echo "$MOONGEN_CLEAN" | awk '/Average rate:/ {print $(NF-3)}' | tail -n1)
MOONGEN_Mbps=$(echo "$MOONGEN_CLEAN" | awk '/Average rate:/ {print $NF}' | tail -n1)

# Extract receiver packet rate (capinfos output)
RECV_PPS=$(echo "$CAPINFOS_OUTPUT" | awk '/Average packet rate:/ {print $5}')
RECV_UNIT=$(echo "$CAPINFOS_OUTPUT" | awk '/Average packet rate:/ {print $6}')

# Normalize receiver rate to Mpps
if [[ "$RECV_UNIT" == "kpackets/s" ]]; then
  RECV_MPPS=$(awk -v p="$RECV_PPS" 'BEGIN {printf "%.3f", p / 1000}')
else
  RECV_MPPS=$(awk -v p="$RECV_PPS" 'BEGIN {printf "%.3f", p}')
fi

echo "================ RATE COMPARISON ================"
printf "Sender (MoonGen): %.3f Mpps, %.3f Mbps\n" "${MOONGEN_MPPS:-0}" "${MOONGEN_Mbps:-0}"
printf "Receiver (tcpdump): %.3f Mpps\n" "${RECV_MPPS:-0}"

if [[ -n "${MOONGEN_MPPS:-}" && -n "${RECV_MPPS:-}" && $(echo "$MOONGEN_MPPS > 0" | bc) -eq 1 ]]; then
  LOSS_PCT=$(awk -v s="$MOONGEN_MPPS" -v r="$RECV_MPPS" 'BEGIN {printf "%.2f", (1 - r/s) * 100}')
  printf "Estimated packet loss: %s%%\n" "$LOSS_PCT"
fi
echo "================================================="
