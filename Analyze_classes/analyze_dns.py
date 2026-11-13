import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']

dns = df[df['Label'] == 'DrDoS_DNS']
print('=== DrDoS_DNS Training Statistics ===')
print('Count:', len(dns))
print()
print('=== Total Packets Per Flow ===')
print('  Mean: %.2f' % dns['Total_Packets_Mean'].mean())
print('  Median: %.2f' % dns['Total_Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Total_Packets_Mean'], p)))
print('  Min: %.2f' % dns['Total_Packets_Mean'].min())
print('  Max: %.2f' % dns['Total_Packets_Mean'].max())
print()

print('=== Forward Packets Per Flow ===')
print('  Mean: %.2f' % dns['Total Fwd Packets_Mean'].mean())
print('  Median: %.2f' % dns['Total Fwd Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Total Fwd Packets_Mean'], p)))
print('  Min: %.2f' % dns['Total Fwd Packets_Mean'].min())
print('  Max: %.2f' % dns['Total Fwd Packets_Mean'].max())
print()

print('=== Backward Packets Per Flow ===')
print('  Mean: %.4f' % dns['Total Backward Packets_Mean'].mean())
print('  Median: %.4f' % dns['Total Backward Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.4f' % (p, np.percentile(dns['Total Backward Packets_Mean'], p)))
print('  Min: %.4f' % dns['Total Backward Packets_Mean'].min())
print('  Max: %.4f' % dns['Total Backward Packets_Mean'].max())
print()

print('=== Flow Duration (microseconds) ===')
print('  Mean: %.2f' % dns['Flow Duration_Mean'].mean())
print('  Median: %.2f' % dns['Flow Duration_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Flow Duration_Mean'], p)))
print('  Min: %.2f' % dns['Flow Duration_Mean'].min())
print('  Max: %.2f' % dns['Flow Duration_Mean'].max())
print()

print('=== Flow Bytes/s ===')
print('  Mean: %.2f' % dns['Flow Bytes/s_Mean'].mean())
print('  Median: %.2f' % dns['Flow Bytes/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Flow Bytes/s_Mean'], p)))
print('  Min: %.2f' % dns['Flow Bytes/s_Mean'].min())
print('  Max: %.2f' % dns['Flow Bytes/s_Mean'].max())
print()

print('=== Flow Packets/s ===')
print('  Mean: %.2f' % dns['Flow Packets/s_Mean'].mean())
print('  Median: %.2f' % dns['Flow Packets/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Flow Packets/s_Mean'], p)))
print('  Min: %.2f' % dns['Flow Packets/s_Mean'].min())
print('  Max: %.2f' % dns['Flow Packets/s_Mean'].max())
print()

print('=== Packet Length Mean ===')
print('  Mean: %.2f' % dns['Packet Length Mean_Mean'].mean())
print('  Median: %.2f' % dns['Packet Length Mean_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Packet Length Mean_Mean'], p)))
print('  Min: %.2f' % dns['Packet Length Mean_Mean'].min())
print('  Max: %.2f' % dns['Packet Length Mean_Mean'].max())
print()

print('=== Packet Length Std ===')
print('  Mean: %.2f' % dns['Packet Length Std_Mean'].mean())
print('  Median: %.2f' % dns['Packet Length Std_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Packet Length Std_Mean'], p)))
print('  Min: %.2f' % dns['Packet Length Std_Mean'].min())
print('  Max: %.2f' % dns['Packet Length Std_Mean'].max())
print()

print('=== Average Packet Size ===')
print('  Mean: %.2f' % dns['Average Packet Size_Mean'].mean())
print('  Median: %.2f' % dns['Average Packet Size_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(dns['Average Packet Size_Mean'], p)))
print('  Min: %.2f' % dns['Average Packet Size_Mean'].min())
print('  Max: %.2f' % dns['Average Packet Size_Mean'].max())
print()

# Packet count distribution
print('=== Packet count distribution ===')
print('  Flows with exactly 2 total packets: %.1f%%' % (100.0 * (dns['Total_Packets_Mean'] == 2).sum() / len(dns)))
print('  Flows with 2-9 total packets: %.1f%%' % (100.0 * ((dns['Total_Packets_Mean'] >= 2) & (dns['Total_Packets_Mean'] < 10)).sum() / len(dns)))
print('  Flows with 10-49 total packets: %.1f%%' % (100.0 * ((dns['Total_Packets_Mean'] >= 10) & (dns['Total_Packets_Mean'] < 50)).sum() / len(dns)))
print('  Flows with 50-99 total packets: %.1f%%' % (100.0 * ((dns['Total_Packets_Mean'] >= 50) & (dns['Total_Packets_Mean'] < 100)).sum() / len(dns)))
print('  Flows with 100+ total packets: %.1f%%' % (100.0 * (dns['Total_Packets_Mean'] >= 100).sum() / len(dns)))

# Backward packet presence
has_bwd = (dns['Total Backward Packets_Mean'] > 0).sum()
print()
print('=== Backward packet presence ===')
print('  Windows with backward packets: %d/%d (%.1f%%)' % (has_bwd, len(dns), 100.0 * has_bwd / len(dns)))
