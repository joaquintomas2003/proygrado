from bcc import BPF

prog = """
int trace_connect(struct pt_regs *ctx) {
    bpf_trace_printk("tcp_v4_connect called\\n");
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

print("Monitoreando conexiones TCP salientes (tcp_v4_connect)...")
try:
    b.trace_print(fmt="{5}")
except KeyboardInterrupt:
    print("Saliendo...")
