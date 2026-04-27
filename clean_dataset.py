"""
ARP Flood Detection - Dataset Cleaner
--------------------------------------
- Removes duplicate rows
- Removes rows where arp_total == 0
- Saves cleaned dataset as a new file (original is untouched)

Dependencies:
    pip install pandas
"""

import pandas as pd
from pathlib import Path


# ── Config ──────────────────────────────────────────────────────────────────
INPUT_PATH  = Path("/opt/p4work/arp_flood_detection/dataset/arp_dataset.csv")
OUTPUT_PATH = INPUT_PATH.parent / "arp_dataset_cleaned.csv"
# ─────────────────────────────────────────────────────────────────────────────


def load_dataset(path: Path) -> pd.DataFrame:
    print(f"[INFO] Loading dataset from: {path}")
    df = pd.read_csv(path)
    print(f"[INFO] Original shape: {df.shape[0]} rows × {df.shape[1]} cols")
    return df


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.drop_duplicates()
    removed = before - len(df)
    print(f"[CLEAN] Removed {removed} duplicate row(s)  →  {len(df)} rows remaining")
    return df


def remove_zero_arp_total(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df[df["arp_total"] != 0]
    removed = before - len(df)
    print(f"[CLEAN] Removed {removed} row(s) where arp_total == 0  →  {len(df)} rows remaining")
    return df


def shuffle_dataset(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[CLEAN] Dataset shuffled  →  {len(df)} rows (order fully randomized)")
    return df


def save_dataset(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False)
    print(f"[INFO] Cleaned dataset saved to: {path}")


def print_distribution(df: pd.DataFrame, title: str) -> None:
    total = len(df)
    print(f"\n  {title}  (total: {total} rows)")
    print("  " + "─" * 50)
    if total == 0:
        print("  (no rows in this group)")
        return
    counts = df["label"].value_counts()
    for label, count in counts.items():
        pct = count / total * 100
        bar = "█" * int(pct / 2)
        print(f"  {str(label):>20} : {count:>6} rows  ({pct:5.1f}%)  {bar}")


def label_summary(df: pd.DataFrame) -> None:
    sep = "═" * 54

    # ── Total distribution ───────────────────────────────────
    print(f"\n{sep}")
    print("  OVERALL CLASS DISTRIBUTION")
    print(sep)
    print_distribution(df, "All rows")

    # ── arp_total > 300 ──────────────────────────────────────
    high = df[df["arp_total"] > 300]
    print(f"\n{sep}")
    print("  CLASS DISTRIBUTION  —  arp_total > 300")
    print(sep)
    print_distribution(high, "arp_total > 300")

    # ── arp_total <= 300 (already > 0 after cleaning) ────────
    low = df[df["arp_total"] <= 300]
    print(f"\n{sep}")
    print("  CLASS DISTRIBUTION  —  arp_total <= 300  (and > 0)")
    print(sep)
    print_distribution(low, "arp_total <= 300")
    print(f"\n{sep}")


def main():
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at: {INPUT_PATH}")

    df = load_dataset(INPUT_PATH)

    df = remove_duplicates(df)
    df = remove_zero_arp_total(df)
    df = shuffle_dataset(df)

    label_summary(df)
    save_dataset(df, OUTPUT_PATH)

    print(f"\n[DONE] Final shape: {df.shape[0]} rows × {df.shape[1]} cols")
    print(f"       Original : {INPUT_PATH}")
    print(f"       Cleaned  : {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
