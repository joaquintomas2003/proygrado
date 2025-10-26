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

# Extract Mpps from MoonGen output
MOONGEN_MPPS=$(grep -E "Average rate" moongen_output.log | tail -n1 | awk '{print $7}')
MOONGEN_Mbps=$(grep -E "Average rate" moongen_output.log | tail -n1 | awk '{print $9}')

# Extract receiver rate (packets/s) from capinfos
RECV_PPS=$(echo "$CAPINFOS_OUTPUT" | grep "Average packet rate" | awk '{print $5}')
RECV_UNIT=$(echo "$CAPINFOS_OUTPUT" | grep "Average packet rate" | awk '{print $6}')

# Normalize receiver rate
if [[ "$RECV_UNIT" == "kpackets/s" ]]; then
  RECV_MPPS=$(awk "BEGIN {print $RECV_PPS / 1000}")
else
  RECV_MPPS=$RECV_PPS
fi

echo "================ RATE COMPARISON ================"
echo "Sender (MoonGen): ${MOONGEN_MPPS:-N/A} Mpps (${MOONGEN_Mbps:-N/A} Mbps)"
echo "Receiver (tcpdump): ${RECV_MPPS:-N/A} Mpps"
if [[ -n "${MOONGEN_MPPS:-}" && -n "${RECV_MPPS:-}" ]]; then
  LOSS_PCT=$(awk "BEGIN {print (1 - $RECV_MPPS / $MOONGEN_MPPS) * 100}")
  echo "Estimated packet loss: ${LOSS_PCT}%"
fi
echo "================================================="
