#!/usr/bin/env python3
"""
Process "entrada.txt" where each line has the form:
X | Y   (Y is a hex number)

Stages:
1) remove the "X | " prefix and keep Y
2) convert Y from hex to decimal
3) count occurrences and write CSV "salida.csv" with "value,count"
"""

import collections
import csv

INPUT_FILE = "entrada.txt"
OUTPUT_FILE = "salida.csv"

def extract_hex_part(line: str) -> str:
    if '|' not in line:
        return ''
    _, _, right = line.partition('|')
    return right.strip()

def hex_to_decimal(hex_str: str) -> int:
    if hex_str.lower().startswith('0x'):
        hex_str = hex_str[2:]
    if hex_str == '':
        raise ValueError("Empty hex string")
    return int(hex_str, 16)

def process_file() -> collections.Counter:
    print("Reading and processing input file...")
    counter = collections.Counter()
    total_lines = 0

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            hex_part = extract_hex_part(line)
            if not hex_part:
                continue

            try:
                dec_value = hex_to_decimal(hex_part)
            except ValueError:
                continue

            counter[dec_value] += 1

    print(f"Processed {total_lines} lines.")
    print(f"Found {len(counter)} unique values.")
    return counter

def write_csv(counter: collections.Counter) -> None:
    print("Writing output CSV...")
    items = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        for value, count in items:
            writer.writerow([value, count])

    print(f"Output written to {OUTPUT_FILE}")
    print("Done.")

def main():
    counts = process_file()
    write_csv(counts)

if __name__ == "__main__":
    main()
