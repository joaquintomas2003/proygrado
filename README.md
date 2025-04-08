# Proyecto de Grado

## Guia setup

### eBPF
#### eBPF con BCC
Para utilizar [BCC (BPF Compiler Collection)](https://github.com/iovisor/bcc/tree/master) como framework utilizamos **Ubuntu `24.04.2`**. Para utilizar otro SO seguir [estas guias](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

- Instalar BCC
```
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm18 llvm-18-dev libclang-18-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf libpolly-18-dev
```
