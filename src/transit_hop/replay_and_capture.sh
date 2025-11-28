#!/usr/bin/env bash
set -euo pipefail

INGRESS_IF="veth1"
EGRESS_IF="veth3"
USER_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
SRC_PCAP="${USER_HOME}/proygrado/traffic-generator/traces/generated_int.pcap"
OUT_PCAP="./output_from_switch.pcap"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -- "$0" "$@"
fi

ip link set "$INGRESS_IF" up || true
ip link set "$EGRESS_IF" up || true
rm -f "$OUT_PCAP"

tcpdump -i "$EGRESS_IF" -U -w "$OUT_PCAP" &
TCPDUMP_PID=$!

trap "kill $TCPDUMP_PID 2>/dev/null || true" EXIT

tcpreplay -i "$INGRESS_IF" "$SRC_PCAP"
sleep 5

kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
trap - EXIT

echo "$OUT_PCAP"
