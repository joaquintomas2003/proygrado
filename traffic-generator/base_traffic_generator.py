from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
import os
import random
import struct
import yaml

# CONFIG
OUTPUT_PCAP = "int_r3_capture.pcap"
NUM_PACKETS = 1_000
PACKET_SIZE = 64  # bytes total

SRC_MAC = "aa:bb:cc:dd:ee:ff"
DST_MAC = "11:22:33:44:55:66"
SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.18"
SRC_PORT = 5432
DST_PORT = 80
PAYLOAD = b"dummy_payload"

INT_UDP_DST_PORT = 5000  # arbitrary INT UDP port
ORIGINAL_PROTO = 6        # TCP
INT_TYPE = 1              # 1 = INT-MD
NPT_L4 = 2                # indicates that another (the original) L4 header follows the INT stack
INSTRUCTION_BITMAP = 0b1010000000000000  # Node ID + Hop Latency (bit 0 + bit 2 where bit 0 is MSB)

# Bit: (Field, Length)
INSTRUCTION_FIELDS = {
    0: ("node_id", 4),
    1: ("iface_l1", 4),
    2: ("hop_latency", 4),
    3: ("queue_info", 4),
    4: ("ing_ts", 8),
    5: ("eg_ts", 8),
    6: ("iface_l2", 8),
    7: ("tx_util", 4),
    8: ("buffer_info", 4),
    15: ("checksum_comp", 4)
}

def load_config():
    path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(path, "r") as f:
        return yaml.safe_load(f)

def build_instruction_bitmap(bits):
    bitmap = 0
    for bit in bits:
        bitmap |= 1 << (15 - bit)
    return bitmap

def compute_hop_ml(bitmap: int) -> int:
    """Returns the Hop ML in 4-byte words"""
    total_bytes = sum(size for bit, (_, size) in INSTRUCTION_FIELDS.items()
                      if bitmap & (1 << (15 - bit)))
    return total_bytes // 4

def build_int_shim(hop_ml, num_hops, original_proto):
    # Type(4b)=1, NPT(2b)=2, Reserved(2b)=0 => 0b0001_10_00 = 0x18
    shim_type = (INT_TYPE << 4) | (NPT_L4 << 2)
    shim_len = 3 + hop_ml * num_hops # INT-MD header + metadata stack
    return struct.pack("!BBH", shim_type, shim_len, original_proto)

def build_int_md_header(hop_ml, rhc, instruction_bitmap):
    ver_d_e_m = 0x20  # version=2, D=0, E=0, M=0
    reserved = 0x00
    part1 = struct.pack("!BBBB", ver_d_e_m, reserved, hop_ml, rhc)

    domain_id = 0x0000
    part2 = struct.pack("!HH", instruction_bitmap, domain_id)

    ds_instr = 0x0000
    ds_flags = 0x0000
    part3 = struct.pack("!HH", ds_instr, ds_flags)

    return part1 + part2 + part3


def generate_metadata_for_hop(node_id, instruction_bitmap):
    metadata = b""
    for bit in range(16):
        if instruction_bitmap & (1 << (15 - bit)):
            name, size = INSTRUCTION_FIELDS.get(bit, ("unknown", 4))
            if name == "node_id":
                value = node_id
                metadata += struct.pack("!I", value)
            elif name == "hop_latency":
                value = random.randint(100, 1000)
                metadata += struct.pack("!I", value)
            elif size == 4:
                metadata += struct.pack("!I", random.randint(0, 2**32 - 1))
            elif size == 8:
                metadata += struct.pack("!Q", random.randint(0, 2**64 - 1))
    return metadata

def build_metadata_stack(hops, instruction_bitmap):
    return b"".join(generate_metadata_for_hop(h, instruction_bitmap) for h in hops)


def generate_int_packet(i, config, instruction_bitmap):
    eth = Ether(src=SRC_MAC, dst=DST_MAC)
    ip = IP(src=SRC_IP, dst=DST_IP)
    udp = UDP(sport=random.randint(1024, 65535), dport=config["int_udp_dst_port"])
    tcp = TCP(sport=SRC_PORT, dport=DST_PORT, seq=i)
    payload = Raw(config["payload"].encode())

    hop_ml = compute_hop_ml(instruction_bitmap)
    shim = build_int_shim(hop_ml, len(config["hops"]), config["original_proto"])
    md_header = build_int_md_header(hop_ml, rhc=1, instruction_bitmap=instruction_bitmap)
    metadata = build_metadata_stack(config["hops"], instruction_bitmap)

    return eth / ip / udp / Raw(shim + md_header + metadata) / tcp / payload

def main():
    config = load_config()
    instruction_bitmap = build_instruction_bitmap(config.get("instruction_bits", []))
    packets = [generate_int_packet(i, config, instruction_bitmap) for i in range(config["num_packets"])]
    wrpcap(config["output_pcap"], packets)
    print(f"{len(packets)} packets written to {config['output_pcap']}")

if __name__ == "__main__":
    main()
