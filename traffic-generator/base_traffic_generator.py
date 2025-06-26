from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import random
import struct

# CONFIG
OUTPUT_PCAP = "int_r3_capture.pcap"
NUM_PACKETS = 1_000
PACKET_SIZE = 64  # bytes total

SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.18"
SRC_PORT = 5432
DST_PORT = 80
PAYLOAD = b"dummy_payload"

INT_UDP_DST_PORT = 5000  # arbitrary INT UDP port
ORIGINAL_PROTO = 6        # TCP
INT_TYPE = 1              # 1 = INT-MD
NPT_L4 = 2                # indicates that another (the original) L4 header follows the INT stack
HOP_METADATA_LEN = 2      # 2 * 4B = 8 bytes per hop
REMAINING_HOPS = 1
INSTRUCTION_BITMAP = 0b1010000000000000  # Node ID + Hop Latency (bit 0 + bit 2 where bit 0 is MSB)


def build_int_shim():
    # Type(4b)=1, NPT(2b)=2, Reserved(2b)=0 => 0b0001_10_00 = 0x18
    shim_type = (INT_TYPE << 4) | (NPT_L4 << 2)
    shim_len = 9  # (INT-MD header + 3 hops * 8 bytes) = 12 + 24 = 36B => 36/4 = 9
    shim_proto = ORIGINAL_PROTO
    return struct.pack("!BBH", shim_type, shim_len, shim_proto)

def build_int_md_header():
    ver_d_e_m = 0x20  # version=2, D=0, E=0, M=0
    reserved = 0x00
    hop_ml = HOP_METADATA_LEN
    rhc = REMAINING_HOPS
    header_part1 = struct.pack("!BBBB", ver_d_e_m, reserved, hop_ml, rhc)

    instruction_bitmap = INSTRUCTION_BITMAP
    domain_id = 0x0000
    part2 = struct.pack("!HH", instruction_bitmap, domain_id)

    ds_instruction = 0x0000
    ds_flags = 0x0000
    part3= struct.pack("!HH", ds_instruction, ds_flags)

    return header_part1 + part2 + part3

def build_metadata_stack():
    hops = [
        (0x03, 500),
        (0x02, 300),
        (0x01, 400),
        ] # TODO: randomizar hop latency siguiendo determinada distribución
    stack = b""
    for node_id, latency in hops:
        stack += struct.pack("!II", node_id, latency)
    return stack

def generate_int_packet(i):
    ip = IP(src=SRC_IP, dst=DST_IP)

    # Outer INT UDP encapsulation
    int_udp = UDP(sport=random.randint(1024, 65535), dport=INT_UDP_DST_PORT)

    # INT headers
    shim = build_int_shim()
    md_header = build_int_md_header()
    metadata = build_metadata_stack()

    # Original TCP + Payload
    tcp = TCP(sport=SRC_PORT, dport=DST_PORT, seq=i)
    payload = Raw(PAYLOAD)

    # Final composition
    pkt = ip / int_udp / Raw(shim + md_header + metadata) / tcp / payload
    return pkt

def main():
    packets = []
    for i in range(NUM_PACKETS):
        pkt = generate_int_packet(i)
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
