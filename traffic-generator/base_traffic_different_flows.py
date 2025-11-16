from scapy.all import Ether, IP, TCP, Raw, wrpcap

OUTPUT_PCAP = "unique_flows_100k.pcap"
NUM_PKTS = 50_000

def idx_to_ip(i: int) -> str:
    """
    Map an integer to a unique IPv4 address in 10.x.y.z
    10.(a).(b).(c), with each octet < 256.
    This gives us up to 16M unique IPs; 100k is no problem.
    """
    a = (i // (256 * 256)) % 256
    b = (i // 256) % 256
    c = i % 256
    return f"10.{a}.{b}.{c}"

def main():
    packets = []

    dst_ip_base = "192.168.0.1"
    dst_port_base = 10_000

    for i in range(NUM_PKTS):
        src_ip = idx_to_ip(i)
        dst_ip = dst_ip_base  # keep dst_ip fixed; src_ip makes the flow unique

        # Make src/dst ports also vary, just to be extra sure flows are unique
        src_port = 10_000 + (i % 50_000)
        dst_port = dst_port_base + (i % 10_000)

        payload = f"flow-{i}".encode()

        pkt = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, seq=i)
            / Raw(load=payload)
        )

        packets.append(pkt)

    print(f"Generated {len(packets)} packets, all with unique 5-tuples.")
    wrpcap(OUTPUT_PCAP, packets)
    print(f"Written to {OUTPUT_PCAP}")

if __name__ == "__main__":
    main()

