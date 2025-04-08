#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/sock.h>

int trace_connect(struct sock *sk) {
    u16 dport = ntohs(sk->__sk_common.skc_dport);
    u32 daddr = sk->__sk_common.skc_daddr;

    bpf_trace_printk("TCP connect to: %d.%d.%d.X",
        daddr & 0xff,
        (daddr >> 8) & 0xff,
        (daddr >> 16) & 0xff);

    bpf_trace_printk("Destination port: %d", dport);
    bpf_trace_printk("------------------------");

    return 0;
}
