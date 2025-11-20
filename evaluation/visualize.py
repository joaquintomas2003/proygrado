#!/usr/bin/env python3
"""
Visualize latency data from salida.csv.
Generates histogram, boxplot, and CDF.
All images are saved into the 'plots/' directory.
"""

import csv
import os
import matplotlib.pyplot as plt

INPUT_CSV = "salida.csv"
OUTPUT_DIR = "plots"
OUT_PREFIX = os.path.join(OUTPUT_DIR, "latency_")

def ensure_output_dir():
    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

def load_values():
    data = []
    with open(INPUT_CSV, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            value = int(row[0])
            count = int(row[1])
            data.extend([value] * count)
    return data

def plot_histogram(data):
    plt.figure()
    plt.grid(True, zorder=0)
    plt.hist(data, bins=40, zorder=3)
    plt.xlabel("Latency")
    plt.ylabel("Frequency")
    plt.title("Latency Histogram")
    plt.tight_layout()
    plt.savefig(OUT_PREFIX + "histogram.png")
    plt.close()

def plot_boxplot(data):
    plt.figure()
    plt.grid(True, zorder=0)
    plt.boxplot(data, vert=True, zorder=3)
    plt.ylabel("Latency")
    plt.title("Latency Boxplot")
    plt.tight_layout()
    plt.savefig(OUT_PREFIX + "boxplot.png")
    plt.close()

def plot_cdf(data):
    sorted_data = sorted(data)
    n = len(sorted_data)
    y = [(i + 1) / n for i in range(n)]

    plt.figure()
    plt.grid(True, zorder=0)
    plt.plot(sorted_data, y, zorder=3)
    plt.xlabel("Latency")
    plt.ylabel("Cumulative Probability")
    plt.title("Latency CDF")
    plt.tight_layout()
    plt.savefig(OUT_PREFIX + "cdf.png")
    plt.close()

def main():
    ensure_output_dir()

    data = load_values()
    if not data:
        print("No data loaded.")
        return

    plot_histogram(data)
    plot_boxplot(data)
    plot_cdf(data)

    print(f"Visualization complete. Images saved in '{OUTPUT_DIR}/'")

if __name__ == "__main__":
    main()
