#!/usr/bin/env python3
"""
Statistical analysis of the decimal values extracted from salida.csv.

- Loads salida.csv (rows: value,count)
- Expands counts into the full sample
- Computes basic statistics
- Detects outliers as values strictly above a chosen percentile (e.g. 99)
- Optionally computes aggressive z-score outliers

All code and comments are in English.
"""

import csv
import statistics
from typing import List, Tuple

INPUT_CSV = "salida.csv"
OUTLIER_PERCENTILE = 97.0  # set to 99.0 for 99th percentile; adjust as needed
USE_ZSCORE = True          # set to False to disable z-score detection
ZSCORE_THRESHOLD = 2.5     # threshold for aggressive z-score method


def load_values() -> List[int]:
    """Load values from salida.csv and expand by count."""
    data = []
    with open(INPUT_CSV, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            value = int(row[0])
            count = int(row[1])
            data.extend([value] * count)
    return data


def percentile(sorted_data: List[int], p: float) -> float:
    """
    Compute the p-th percentile (0 <= p <= 100) using linear interpolation
    on the sorted_data. Behavior matches common definitions (interpolated).
    """
    if not sorted_data:
        raise ValueError("Empty data for percentile calculation")
    if p <= 0:
        return float(sorted_data[0])
    if p >= 100:
        return float(sorted_data[-1])

    n = len(sorted_data)
    # position in [0, n-1]
    pos = (p / 100.0) * (n - 1)
    lower_idx = int(pos // 1)
    upper_idx = min(lower_idx + 1, n - 1)
    fraction = pos - lower_idx
    lower_val = sorted_data[lower_idx]
    upper_val = sorted_data[upper_idx]
    return lower_val + fraction * (upper_val - lower_val)


def zscore_outliers(data: List[int], threshold: float = 2.5) -> Tuple[float, float, List[int], List[int]]:
    """
    Return (mean, std, low_outliers, high_outliers) using z-score threshold.
    """
    if len(data) < 2:
        return (float('nan'), float('nan'), [], [])
    mean = statistics.mean(data)
    std = statistics.stdev(data)
    low = []
    high = []
    for x in data:
        if std == 0:
            z = 0.0
        else:
            z = (x - mean) / std
        if z > threshold:
            high.append(x)
        elif z < -threshold:
            low.append(x)
    return mean, std, low, high


def main():
    print("Loading data from", INPUT_CSV)
    data = load_values()
    if not data:
        print("No data loaded. Exiting.")
        return

    data.sort()
    n = len(data)

    minimum = data[0]
    maximum = data[-1]
    mean = statistics.mean(data)
    median = statistics.median(data)
    q1 = percentile(data, 25.0)
    q3 = percentile(data, 75.0)
    std = statistics.stdev(data) if n > 1 else 0.0

    # Percentile-based outliers: everything strictly above the chosen percentile
    threshold = percentile(data, OUTLIER_PERCENTILE)
    percentile_outliers = [x for x in data if x > threshold]

    print("\n=== Statistical Summary ===")
    print(f"Count: {n}")
    print(f"Min: {minimum}")
    print(f"Max: {maximum}")
    print(f"Mean: {mean}")
    print(f"Median: {median}")
    print(f"Q1: {q1}")
    print(f"Q3: {q3}")
    print(f"Std Dev: {std:.6f}")

    print("\n=== Percentile-based Outliers ===")
    print(f"Outlier percentile: {OUTLIER_PERCENTILE}th")
    print(f"Threshold value (percentile): {threshold}")
    print(f"Number of outliers (> threshold): {len(percentile_outliers)}")

if __name__ == "__main__":
    main()