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

# Strip color codes from MoonGen log just in case
MOONGEN_CLEAN=$(sed 's/\x1B\[[0-9;]*[A-Za-z]//g' moongen_output.log)

# Parse numeric values from MoonGen output
MOONGEN_MPPS=$(echo "$MOONGEN_CLEAN" | grep -Eo 'Average rate: [0-9.]+ Mpps' | tail -n1 | awk '{print $3}')
MOONGEN_Mbps=$(echo "$MOONGEN_CLEAN" | grep -Eo 'Average rate: [0-9.]+ Mpps, [0-9.]+ Mbps' | tail -n1 | grep -Eo '[0-9.]+ Mbps' | awk '{print $1}')

# Parse receiver packet rate line (handles "1226 kpackets/s", "1.23 Mpackets/s", or "123456 packets/s")
RECV_LINE=$(echo "$CAPINFOS_OUTPUT" | grep -E "Average packet rate")

# Extract the numeric value *immediately before* the unit
RECV_VALUE=$(echo "$RECV_LINE" | grep -Eo '[0-9.]+[[:space:]]*[kM]?packets/s' | grep -Eo '[0-9.]+')
RECV_UNIT=$(echo "$RECV_LINE" | grep -Eo '[kM]?packets/s')

# Convert receiver rate to Mpps
case "$RECV_UNIT" in
  kpackets/s) RECV_MPPS=$(awk -v v="$RECV_VALUE" 'BEGIN {printf "%.3f", v/1000}') ;;
  Mpackets/s) RECV_MPPS=$(awk -v v="$RECV_VALUE" 'BEGIN {printf "%.3f", v}') ;;
  packets/s)  RECV_MPPS=$(awk -v v="$RECV_VALUE" 'BEGIN {printf "%.6f", v/1e6}') ;;
  *)          RECV_MPPS=0 ;;
esac

echo "================ RATE COMPARISON ================"
printf "Sender (MoonGen): %.3f Mpps, %.3f Mbps\n" "${MOONGEN_MPPS:-0}" "${MOONGEN_Mbps:-0}"
printf "Receiver (tcpdump): %.3f Mpps\n" "${RECV_MPPS:-0}"

# Compute packet loss percentage
if [[ -n "${MOONGEN_MPPS:-}" && -n "${RECV_MPPS:-}" && $(echo "$MOONGEN_MPPS > 0" | bc) -eq 1 ]]; then
  LOSS_PCT=$(awk -v s="$MOONGEN_MPPS" -v r="$RECV_MPPS" 'BEGIN {printf "%.2f", (1 - r/s) * 100}')
  printf "Estimated packet loss: %s%%\n" "$LOSS_PCT"
fi
echo "================================================="
