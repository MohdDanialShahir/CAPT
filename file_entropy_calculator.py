import math
import os
import sys
from collections import Counter


def calculate_file_entropy(file_path):
  with open(file_path, "rb") as f:
    data = f.read()

  if not data:
    return 0.0

  file_size = len(data)
  byte_counts = Counter(data)

  entropy = 0.0
  for count in byte_counts.values():
    p = count / file_size
    entropy -= p * math.log2(p)

  return entropy


if __name__ == "__main__":
  targets = sys.argv[1:] if len(sys.argv) > 1 else ["Act 854.pdf", "Canary_Gantt_Chart.xlsx"]

  for file_path in targets:
    if os.path.exists(file_path):
      entropy = calculate_file_entropy(file_path)
      print(f"File: {file_path}")
      print(f"  Entropy: {entropy:.4f} / 8.0000 bits/byte")
    else:
      print(f"File not found: {file_path}")
