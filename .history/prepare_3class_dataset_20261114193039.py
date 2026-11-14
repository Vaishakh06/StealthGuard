"""
StealthGuard - 3-Class Dataset Preparation
===========================================

Reads the original 17-class engineered_dataset.csv and produces
engineered_3class.csv with BENIGN / TCP_DDoS / UDP_DDoS labels.

The original 17-class dataset is NOT modified.

Label mapping (CIC-DDoS2019 -> 3-class):

BENIGN class:
    BENIGN   -> BENIGN

TCP_DDoS class:
    Syn             -> TCP_DDoS
    Portmap         -> TCP_DDoS
    MSSQL           -> TCP_DDoS
    DrDoS_MSSQL     -> TCP_DDoS

UDP_DDoS class:
    DrDoS_DNS       -> UDP_DDoS
    DrDoS_NTP       -> UDP_DDoS
    DrDoS_SNMP      -> UDP_DDoS
    DrDoS_NetBIOS   -> UDP_DDoS
    DrDoS_SSDP      -> UDP_DDoS
    DrDoS_UDP       -> UDP_DDoS
    TFTP            -> UDP_DDoS
    UDP             -> UDP_DDoS
    UDP-lag         -> UDP_DDoS
    UDPLag          -> UDP_DDoS
    DrDoS_LDAP      -> UDP_DDoS
    NetBIOS         -> UDP_DDoS
    LDAP            -> UDP_DDoS   <-- CORRECTED: LDAP is an attack class
                                                (LDAP reflection/amplification)
                                                in CIC-DDoS2019, not benign.

LDAP MAPPING NOTE:
------------------
The previous mapping placed LDAP under BENIGN. LDAP (93,552 rows) is a
separate attack class in CIC-DDoS2019 (distinct from DrDoS_LDAP) and uses
UDP (port 389) for reflection/amplification attacks. It has been moved to
UDP_DDoS. If you prefer the previous behavior (LDAP -> BENIGN), change the
LABEL_MAP entry below and regenerate.

Output: dataset/engineered/engineered_3class.csv
        (49 columns: 48 features + Label)
"""

import os
import csv
import shutil
from collections import Counter

PROJECT_ROOT = r'/content/drive/MyDrive/StealthGuard'
SOURCE_CSV = os.path.join(PROJECT_ROOT, 'dataset', 'engineered', 'engineered_dataset.csv')
OUTPUT_CSV = os.path.join(PROJECT_ROOT, 'dataset', 'engineered', 'engineered_3class.csv')

CHUNK_SIZE = 100000

# 17-class -> 3-class mapping
LABEL_MAP = {
    # BENIGN class (non-attack)
    'BENIGN': 'BENIGN',
    # TCP_DDoS classes
    'Syn': 'TCP_DDoS',
    'Portmap': 'TCP_DDoS',
    'MSSQL': 'TCP_DDoS',
    'DrDoS_MSSQL': 'TCP_DDoS',
    # UDP_DDoS classes
    'DrDoS_DNS': 'UDP_DDoS',
    'DrDoS_NTP': 'UDP_DDoS',
    'DrDoS_SNMP': 'UDP_DDoS',
    'DrDoS_NetBIOS': 'UDP_DDoS',
    'DrDoS_SSDP': 'UDP_DDoS',
    'DrDoS_UDP': 'UDP_DDoS',
    'TFTP': 'UDP_DDoS',
    'UDP': 'UDP_DDoS',
    'UDP-lag': 'UDP_DDoS',
    'UDPLag': 'UDP_DDoS',
    'DrDoS_LDAP': 'UDP_DDoS',
    'NetBIOS': 'UDP_DDoS',
    'LDAP': 'UDP_DDoS',   # CORRECTED: was BENIGN, now UDP_DDoS (attack class)
}

CLASS_NAMES = ['BENIGN', 'TCP_DDoS', 'UDP_DDoS']


def main():
    print("=" * 70)
    print("STEALTHGUARD 3-CLASS DATASET PREPARATION")
    print("=" * 70)
    print(f"Source:  {SOURCE_CSV}")
    print(f"Output:  {OUTPUT_CSV}")
    print()

    if not os.path.exists(SOURCE_CSV):
        raise FileNotFoundError(f"Source CSV not found: {SOURCE_CSV}")

    # Count source labels
    source_counts = Counter()
    with open(SOURCE_CSV, 'r') as f:
        header = f.readline()
        for line in f:
            parts = line.strip().split(',')
            label = parts[-1]
            source_counts[label] += 1

    print(f"Source unique labels: {len(source_counts)}")
    print(f"Source total rows: {sum(source_counts.values()):,}")
    print()

    # Verify all source labels are mapped
    unmapped = set(source_counts.keys()) - set(LABEL_MAP.keys())
    if unmapped:
        print(f"WARNING: {len(unmapped)} unmapped labels found:")
        for label in sorted(unmapped):
            print(f"  {label:20} ({source_counts[label]:,} rows)")
        raise ValueError(f"Unmapped labels: {unmapped}")

    # Backup existing output if present
    if os.path.exists(OUTPUT_CSV):
        backup = OUTPUT_CSV + '.bak'
        shutil.copy2(OUTPUT_CSV, backup)
        print(f"Existing output backed up to: {backup}")

    # Write mapped dataset
    total_rows = 0
    class_counts = Counter()
    mapped_rows = 0

    with open(SOURCE_CSV, 'r') as fin:
        header = fin.readline()
        with open(OUTPUT_CSV, 'w', newline='') as fout:
            fout.write(header)
            for line in fin:
                parts = line.strip().split(',')
                label = parts[-1]
                if label in LABEL_MAP:
                    parts[-1] = LABEL_MAP[label]
                    fout.write(','.join(parts) + '\n')
                    class_counts[LABEL_MAP[label]] += 1
                    mapped_rows += 1
                total_rows += 1

                if total_rows % 500000 == 0:
                    print(f"  Processed {total_rows:,} rows...")

    print(f"\nTotal rows processed: {total_rows:,}")
    print(f"Total rows mapped:    {mapped_rows:,}")
    print()
    print("3-CLASS DISTRIBUTION:")
    for cls in CLASS_NAMES:
        print(f"  {cls:15} {class_counts[cls]:,}  ({class_counts[cls]/total_rows*100:.1f}%)")
    print(f"  {'TOTAL':15} {total_rows:,}")
    print()
    print(f"Output saved to: {OUTPUT_CSV}")
    print(f"Output file size: {os.path.getsize(OUTPUT_CSV) / (1024**3):.2f} GB")
    print()
    print("=" * 70)
    print("DATASET PREPARATION COMPLETE")
    print("=" * 70)


if __name__ == '__main__':
    main()
