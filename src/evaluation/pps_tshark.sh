#!/usr/bin/env bash
set -euo pipefail

PCAP="$1"

# Extract ALL timestamps
mapfile -t ts < <(tshark -r "$PCAP" -T fields -e frame.time_epoch)

total=${#ts[@]}

if (( total <= 200 )); then
    echo "Not enough packets (need >200)" >&2
    exit 1
fi

first_ts=${ts[100]}
last_ts=${ts[total-101]}

# Count packets in that trimmed range
num_packets=$(( total - 200 ))

duration=$(echo "$last_ts - $first_ts" | bc -l)
pps=$(echo "$num_packets / $duration" | bc -l)

echo "Packets (after trimming): $num_packets"
echo "Duration:                 $duration seconds"
echo "PPS:                       $pps packets/sec"
