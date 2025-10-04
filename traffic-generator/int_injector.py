from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap, rdpcap, PcapWriter
import os
import random
import struct
import yaml
import ipaddress
import math

INT_UDP_DST_PORT = 5000  # arbitrary INT UDP port
ORIGINAL_PROTO = 6        # TCP
INT_TYPE = 1              # 1 = INT-MD
NPT_L4 = 2                # indicates that another (the original) L4 header follows the INT stack

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

def build_instruction_bitmap(bits):
    bitmap = 0
    for bit in bits:
        bitmap |= 1 << (15 - bit)
    return bitmap

def compute_hop_ml(bitmap: int) -> int:
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


def exp_int_sample(scale, max_value, rng=random):
    if scale <= 0:
        return 0
    u = rng.random()
    val = -scale * math.log(1.0 - u)  # exponential with mean=scale
    v_int = int(min(max_value, max(0, round(val))))
    return v_int

def gen_metadata_field_for_name(name, params, rng=random):
    if name == "hop_latency":
        # use microseconds / nanoseconds depending on your desired unit - we'll use microseconds here
        return exp_int_sample(params.get("hop_latency_mean", 200.0), params.get("hop_latency_max", 5000), rng)
    if name == "queue_info":
        return exp_int_sample(params.get("queue_mean", 10.0), params.get("queue_max", 300), rng)
    if name in ("ing_ts", "eg_ts"):
        # timestamp-like: use 64-bit ns counter (randomly close)
        # we generate a 64-bit integer limited to some reasonable window
        return rng.getrandbits(48)  # 48 bits gives large range; you can tune
    if name in ("iface_l1", "iface_l2"):
        return rng.randint(0, 2**(8 if name=="iface_l2" else 32) - 1)
    if name == "tx_util":
        # 0..100 percent (map into 32-bit field)
        return rng.randint(0, 100)
    if name == "buffer_info":
        return rng.randint(0, 2**32 - 1)
    if name == "checksum_comp":
        return rng.randint(0, 2**32 - 1)
    # fallback 32-bit random
    return rng.randint(0, 2**32 - 1)

def generate_metadata_for_hop(node_id, instruction_bitmap, params, rng=random):
    metadata = b""
    for bit in range(16):
        if instruction_bitmap & (1 << (15 - bit)):
            name, size = INSTRUCTION_FIELDS.get(bit, ("unknown", 4))
            if name == "node_id":
                value = node_id
                metadata += struct.pack("!I", value)
            else:
                value = gen_metadata_field_for_name(name, params, rng)
                if size == 4:
                    metadata += struct.pack("!I", value & 0xffffffff)
                elif size == 8:
                    metadata += struct.pack("!Q", value & 0xffffffffffffffff)
    return metadata

def build_metadata_stack(hops, instruction_bitmap, params, rng):
    return b"".join(generate_metadata_for_hop(h, instruction_bitmap, params, rng) for h in hops)

def process_trace(cfg):
    input_pcap = cfg["input_pcap"]
    output_pcap = cfg["output_pcap"]
    int_udp_dst_port = cfg.get("int_udp_dst_port", 5000)

    rng = random.Random(cfg.get("random_seed", None))

    # distribution params for metadata generator
    params = cfg.get("distributions", {
        "hop_latency_mean": 200.0,
        "hop_latency_max": 5000,
        "queue_mean": 10.0,
        "queue_max": 300,
    })

    print(f"Loading {input_pcap} ...")
    in_packets = rdpcap(input_pcap)
    print(f"Read {len(in_packets)} packets")

    limit = cfg.get("num_packets", None)
    if limit:
        in_packets = in_packets[:limit]
        print(f"Using first {len(in_packets)} packets (limit configured)")

    out_packets = []
    written = 0

    for idx, pkt in enumerate(in_packets):
        if not pkt.haslayer(IP):
            continue

        # --- metadata config ---
        hop_ids = cfg.get("hops", [1,2,3,4,5])
        num_hops = len(hop_ids)
        chosen_bits = cfg.get("instruction_bits", [0, 2, 3, 7])
        instruction_bitmap = build_instruction_bitmap(chosen_bits)
        hop_ml = compute_hop_ml(instruction_bitmap)

        # build shim and md header
        original_proto = pkt[IP].proto
        shim = build_int_shim(hop_ml, num_hops, original_proto)
        md_header = build_int_md_header(hop_ml, rhc=0, instruction_bitmap=instruction_bitmap)
        metadata_stack = build_metadata_stack(hop_ids, instruction_bitmap, params, rng)

        # original L4 bytes (transport header + payload)
        orig_transport_and_payload = bytes(pkt[IP].payload)

        # final raw payload for INT
        int_payload = shim + md_header + metadata_stack + orig_transport_and_payload

        # Build L2: preserve MACs if present, but ensure eth.type == IPv4
        if pkt.haslayer(Ether):
            eth = Ether(src=pkt[Ether].src, dst=pkt[Ether].dst, type=0x0800)
        else:
            eth = Ether(type=0x0800)

        # Fresh outer IP (proto=17)
        outer_ip = IP(src=pkt[IP].src, dst=pkt[IP].dst, ttl=pkt[IP].ttl, proto=17)

        # Outer UDP
        if pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
        elif pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
        else:
            src_port = rng.randint(1024, 65535)
        udp_int = UDP(sport=src_port, dport=int_udp_dst_port)

        # Compose
        new_pkt = eth / outer_ip / udp_int / Raw(int_payload)

        # Force recompute: serialize and reparse
        try:
            raw = bytes(new_pkt)
            new_pkt = Ether(raw)
        except Exception as e:
            # fallback: delete stale fields and try again
            for L in [IP, UDP]:
                if new_pkt.haslayer(L):
                    try:
                        delattr(new_pkt[L], "len")
                    except Exception:
                        pass
                    try:
                        delattr(new_pkt[L], "chksum")
                    except Exception:
                        pass
            raw = bytes(new_pkt)
            new_pkt = Ether(raw)

        out_packets.append(new_pkt)
        written += 1

    wrpcap(output_pcap, out_packets)
    print(f"Done. Wrote {written} packets to {output_pcap}")

def load_config():
    path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(path, "r") as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    cfg = load_config()
    process_trace(cfg)
