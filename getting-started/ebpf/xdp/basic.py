from bcc import BPF
import socket

# Define the BPF program that hooks into XDP
prog = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

int xdp_tcp_ip(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);
    if (eth == NULL) {
        return XDP_DROP;
    }
    
    // Check if it's an IP packet (ETH_P_IP)
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if (ip == NULL) {
            return XDP_DROP;
        }
        
        // Check if it's a TCP packet (IPPROTO_TCP)
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)((char *)ip + (ip->ihl * 4));
            if (tcp == NULL) {
                return XDP_DROP;
            }
            
            // Preprocess the IP and TCP data into a formatted string
            char ip_str[40];
            bpf_snprintf(ip_str, sizeof(ip_str), 
                "%d.%d.%d.%d -> %d.%d.%d.%d | %d:%d -> %d:%d", 
                (ip->saddr >> 0) & 0xFF, (ip->saddr >> 8) & 0xFF, 
                (ip->saddr >> 16) & 0xFF, (ip->saddr >> 24) & 0xFF, 
                (ip->daddr >> 0) & 0xFF, (ip->daddr >> 8) & 0xFF, 
                (ip->daddr >> 16) & 0xFF, (ip->daddr >> 24) & 0xFF,
                ntohs(tcp->source), ntohs(tcp->dest));

            // Print the preprocessed string
            bpf_trace_printk("TCP Packet: %s\\n", ip_str);
        }
    }
    return XDP_PASS;
}
"""

# Load the BPF program
b = BPF(text=prog)

# Attach the program to the network interface (e.g., eth0 or ens33)
interface = "eth0"
b.attach_xdp(interface, 0)  # 0 corresponds to XDP_DROP action

print(f"XDP program loaded and attached to {interface}. Monitoring TCP packets...")

# The BPF trace output will be printed to /sys/kernel/debug/tracing/trace_pipe
# We can read from the trace pipe in Python to print output

try:
    while True:
        with open("/sys/kernel/debug/tracing/trace_pipe", "r") as f:
            print(f.readline(), end="")
except KeyboardInterrupt:
    print("Detaching XDP program...")
    b.remove_xdp(interface)
