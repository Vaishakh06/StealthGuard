import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']

syn = df[df['Label'] == 'Syn']
print('=== SYN Training Statistics ===')
print('Count:', len(syn))
print()

print('=== Total Packets Per Flow ===')
print('  Mean: %.2f' % syn['Total_Packets_Mean'].mean())
print('  Median: %.2f' % syn['Total_Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Total_Packets_Mean'], p)))
print('  Min: %.2f' % syn['Total_Packets_Mean'].min())
print('  Max: %.2f' % syn['Total_Packets_Mean'].max())
print()

print('=== Forward Packets Per Flow ===')
print('  Mean: %.2f' % syn['Total Fwd Packets_Mean'].mean())
print('  Median: %.2f' % syn['Total Fwd Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Total Fwd Packets_Mean'], p)))
print('  Min: %.2f' % syn['Total Fwd Packets_Mean'].min())
print('  Max: %.2f' % syn['Total Fwd Packets_Mean'].max())
print()

print('=== Backward Packets Per Flow ===')
print('  Mean: %.2f' % syn['Total Backward Packets_Mean'].mean())
print('  Median: %.2f' % syn['Total Backward Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Total Backward Packets_Mean'], p)))
print('  Min: %.2f' % syn['Total Backward Packets_Mean'].min())
print('  Max: %.2f' % syn['Total Backward Packets_Mean'].max())
print()

print('=== Flow Duration (microseconds) ===')
print('  Mean: %.2f' % syn['Flow Duration_Mean'].mean())
print('  Median: %.2f' % syn['Flow Duration_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Flow Duration_Mean'], p)))
print('  Min: %.2f' % syn['Flow Duration_Mean'].min())
print('  Max: %.2f' % syn['Flow Duration_Mean'].max())
print()

print('=== Flow Bytes/s ===')
print('  Mean: %.2f' % syn['Flow Bytes/s_Mean'].mean())
print('  Median: %.2f' % syn['Flow Bytes/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Flow Bytes/s_Mean'], p)))
print('  Min: %.2f' % syn['Flow Bytes/s_Mean'].min())
print('  Max: %.2f' % syn['Flow Bytes/s_Mean'].max())
print()

print('=== Flow Packets/s ===')
print('  Mean: %.2f' % syn['Flow Packets/s_Mean'].mean())
print('  Median: %.2f' % syn['Flow Packets/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Flow Packets/s_Mean'], p)))
print('  Min: %.2f' % syn['Flow Packets/s_Mean'].min())
print('  Max: %.2f' % syn['Flow Packets/s_Mean'].max())
print()

print('=== Packet Length Mean ===')
print('  Mean: %.2f' % syn['Packet Length Mean_Mean'].mean())
print('  Median: %.2f' % syn['Packet Length Mean_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Packet Length Mean_Mean'], p)))
print('  Min: %.2f' % syn['Packet Length Mean_Mean'].min())
print('  Max: %.2f' % syn['Packet Length Mean_Mean'].max())
print()

print('=== Packet Length Std ===')
print('  Mean: %.2f' % syn['Packet Length Std_Mean'].mean())
print('  Median: %.2f' % syn['Packet Length Std_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Packet Length Std_Mean'], p)))
print('  Min: %.2f' % syn['Packet Length Std_Mean'].min())
print('  Max: %.2f' % syn['Packet Length Std_Mean'].max())
print()

print('=== Average Packet Size ===')
print('  Mean: %.2f' % syn['Average Packet Size_Mean'].mean())
print('  Median: %.2f' % syn['Average Packet Size_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(syn['Average Packet Size_Mean'], p)))
print('  Min: %.2f' % syn['Average Packet Size_Mean'].min())
print('  Max: %.2f' % syn['Average Packet Size_Mean'].max())
print()

# Packet count distribution
print('=== Packet count distribution ===')
print('  Flows with exactly 2 total packets: %.1f%%' % (100.0 * (syn['Total_Packets_Mean'] == 2).sum() / len(syn)))
print('  Flows with exactly 3 total packets: %.1f%%' % (100.0 * (syn['Total_Packets_Mean'] == 3).sum() / len(syn)))
print('  Flows with 2-9 total packets: %.1f%%' % (100.0 * ((syn['Total_Packets_Mean'] >= 2) & (syn['Total_Packets_Mean'] < 10)).sum() / len(syn)))
print('  Flows with 10-49 total packets: %.1f%%' % (100.0 * ((syn['Total_Packets_Mean'] >= 10) & (syn['Total_Packets_Mean'] < 50)).sum() / len(syn)))
print('  Flows with 50-99 total packets: %.1f%%' % (100.0 * ((syn['Total_Packets_Mean'] >= 50) & (syn['Total_Packets_Mean'] < 100)).sum() / len(syn)))
print('  Flows with 100+ total packets: %.1f%%' % (100.0 * (syn['Total_Packets_Mean'] >= 100).sum() / len(syn)))

# Backward packet presence
has_bwd = (syn['Total Backward Packets_Mean'] > 0).sum()
print()
print('=== Backward packet presence ===')
print('  Windows with backward packets: %d/%d (%.1f%%)' % (has_bwd, len(syn), 100.0 * has_bwd / len(syn)))

# Forward/Backward ratio for flows that have both
fwd_only = (syn['Total Backward Packets_Mean'] == 0).sum()
bwd_present = len(syn) - fwd_only
print()
print('=== Forward-only vs bidirectional ===')
print('  Forward-only windows: %d/%d (%.1f%%)' % (fwd_only, len(syn), 100.0 * fwd_only / len(syn)))
print('  Bidirectional windows: %d/%d (%.1f%%)' % (bwd_present, len(syn), 100.0 * bwd_present / len(syn)))

# SYN vs TFTP comparison
print()
print('=== SYN vs TFTP Training Comparison ===')
tftp = df[df['Label'] == 'TFTP']
features = ['Total Fwd Packets_Mean', 'Total Backward Packets_Mean', 'Packet Length Mean_Mean',
            'Packet Length Std_Mean', 'Average Packet Size_Mean', 'Flow Duration_Mean',
            'Flow Bytes/s_Mean', 'Flow Packets/s_Mean']
print('%-35s %15s %15s' % ('Feature', 'SYN Median', 'TFTP Median'))
print('-' * 80)
for feat in features:
    syn_med = np.median(syn[feat])
    tftp_med = np.median(tftp[feat])
    print('%-35s %15.2f %15.2f' % (feat, syn_med, tftp_med))
