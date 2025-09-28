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

def load_config():
    path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(path, "r") as f:
        return yaml.safe_load(f)
