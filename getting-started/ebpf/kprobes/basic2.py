from bcc import BPF

with open("basic2.c") as f:
    prog = f.read()

b = BPF(text=prog)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")

print("Monitoreando conexiones TCP salientes (tcp_v4_connect)...")
try:
    b.trace_print(fmt="{5}")
except KeyboardInterrupt:
    print("Saliendo...")
