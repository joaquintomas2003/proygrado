import os
import subprocess
import yaml

BASE_CONFIG = "config.yaml"
OUT_BASE = "traces/int_injected"
SCRIPT = "int_injector.py"

# Instruction bit combinations
INSTRUCTION_SETS = [
    [0],
    [0, 2],
    [0, 2, 3],
    [0, 2, 3, 7],
]

# Request hop lists
HOP_SETS = [
    [1],
    [1, 2],
    [1, 2, 3],
    [1, 2, 3, 4],
    [1, 2, 3, 4, 5],
]

# Response hop lists
REVERSE_HOP_SETS = [
    [6],
    [7, 6],
    [8, 7, 6],
    [9, 8, 7, 6],
    [10, 9, 8, 7, 6],
]

def load_base_config():
    with open(BASE_CONFIG, "r") as f:
        return yaml.safe_load(f)

def save_temp_config(cfg, path):
    with open(path, "w") as f:
        yaml.safe_dump(cfg, f)

def run_generation(cfg_path):
    subprocess.run(["python3", SCRIPT], check=True)

def main():
    os.makedirs(OUT_BASE, exist_ok=True)

    for idx, hops in enumerate(HOP_SETS):
        reverse_hops = REVERSE_HOP_SETS[idx]

        hop_dir = os.path.join(OUT_BASE, f"{len(hops)}node")
        os.makedirs(hop_dir, exist_ok=True)

        for inst_idx, instruction_bits in enumerate(INSTRUCTION_SETS, start=1):
            cfg = load_base_config()

            cfg["forward_hops"] = hops
            cfg["reverse_hops"] = reverse_hops
            cfg["instruction_bits"] = instruction_bits

            output_pcap = os.path.join(hop_dir, f"{inst_idx}instructions.pcap")
            cfg["output_pcap"] = output_pcap

            temp_cfg_path = "config.yaml"
            save_temp_config(cfg, temp_cfg_path)

            print(f"\nRunning for:")
            print(f"  forward_hops={hops}")
            print(f"  reverse_hops={reverse_hops}")
            print(f"  instructions={instruction_bits}")
            print(f"  → Output: {output_pcap}")

            run_generation(temp_cfg_path)

    print("\nAll combinations processed.")

if __name__ == "__main__":
    main()
