from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import random

# CONFIG
OUTPUT_PCAP = "base_traffic.pcap"
NUM_PACKETS = 1_000_000
PACKET_SIZE = 64  # bytes total
SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.18"
SRC_PORT = 5432
DST_PORT = 80
PAYLOAD = b"dummy_payload"

def generate_packet(i):
    pkt = IP(src=SRC_IP, dst=DST_IP) / TCP(sport=SRC_PORT, dport=DST_PORT, seq=i) / Raw(load=PAYLOAD)
    return pkt

def main():
    packets = []
    for i in range(NUM_PACKETS):
        pkt = generate_packet(i)
        packets.append(pkt)

        # flush to disk every N packets to save memory
        if len(packets) >= 10000:
            print(f"{len(packets)} packets")
            wrpcap(OUTPUT_PCAP, packets, append=True)
            packets.clear()

    if packets:
        wrpcap(OUTPUT_PCAP, packets, append=True)

    print(f"Done! {NUM_PACKETS} packets written to {OUTPUT_PCAP}")

if __name__ == "__main__":
    main()
