import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']

ntp = df[df['Label'] == 'DrDoS_NTP']
print('=== DrDoS_NTP Training Statistics ===')
print('Count:', len(ntp))
print()

# Overall packet count stats
print('=== Total Packets Per Flow ===')
print('  Mean: %.2f' % ntp['Total_Packets_Mean'].mean())
print('  Median: %.2f' % ntp['Total_Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Total_Packets_Mean'], p)))
print('  Min: %.2f' % ntp['Total_Packets_Mean'].min())
print('  Max: %.2f' % ntp['Total_Packets_Mean'].max())
print()

# Forward/Backward packet counts
print('=== Forward Packets Per Flow ===')
print('  Mean: %.2f' % ntp['Total Fwd Packets_Mean'].mean())
print('  Median: %.2f' % ntp['Total Fwd Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Total Fwd Packets_Mean'], p)))
print('  Min: %.2f' % ntp['Total Fwd Packets_Mean'].min())
print('  Max: %.2f' % ntp['Total Fwd Packets_Mean'].max())
print()

print('=== Backward Packets Per Flow ===')
print('  Mean: %.2f' % ntp['Total Backward Packets_Mean'].mean())
print('  Median: %.2f' % ntp['Total Backward Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Total Backward Packets_Mean'], p)))
print('  Min: %.2f' % ntp['Total Backward Packets_Mean'].min())
print('  Max: %.2f' % ntp['Total Backward Packets_Mean'].max())
print()

# Flow Duration
print('=== Flow Duration (microseconds) ===')
print('  Mean: %.2f' % ntp['Flow Duration_Mean'].mean())
print('  Median: %.2f' % ntp['Flow Duration_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Flow Duration_Mean'], p)))
print('  Min: %.2f' % ntp['Flow Duration_Mean'].min())
print('  Max: %.2f' % ntp['Flow Duration_Mean'].max())
print()

# Flow Bytes/s
print('=== Flow Bytes/s ===')
print('  Mean: %.2f' % ntp['Flow Bytes/s_Mean'].mean())
print('  Median: %.2f' % ntp['Flow Bytes/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Flow Bytes/s_Mean'], p)))
print('  Min: %.2f' % ntp['Flow Bytes/s_Mean'].min())
print('  Max: %.2f' % ntp['Flow Bytes/s_Mean'].max())
print()

# Flow Packets/s
print('=== Flow Packets/s ===')
print('  Mean: %.2f' % ntp['Flow Packets/s_Mean'].mean())
print('  Median: %.2f' % ntp['Flow Packets/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Flow Packets/s_Mean'], p)))
print('  Min: %.2f' % ntp['Flow Packets/s_Mean'].min())
print('  Max: %.2f' % ntp['Flow Packets/s_Mean'].max())
print()

# Packet Length Mean
print('=== Packet Length Mean ===')
print('  Mean: %.2f' % ntp['Packet Length Mean_Mean'].mean())
print('  Median: %.2f' % ntp['Packet Length Mean_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Packet Length Mean_Mean'], p)))
print('  Min: %.2f' % ntp['Packet Length Mean_Mean'].min())
print('  Max: %.2f' % ntp['Packet Length Mean_Mean'].max())
print()

# Packet Length Std
print('=== Packet Length Std ===')
print('  Mean: %.2f' % ntp['Packet Length Std_Mean'].mean())
print('  Median: %.2f' % ntp['Packet Length Std_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Packet Length Std_Mean'], p)))
print('  Min: %.2f' % ntp['Packet Length Std_Mean'].min())
print('  Max: %.2f' % ntp['Packet Length Std_Mean'].max())
print()

# Average Packet Size
print('=== Average Packet Size ===')
print('  Mean: %.2f' % ntp['Average Packet Size_Mean'].mean())
print('  Median: %.2f' % ntp['Average Packet Size_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ntp['Average Packet Size_Mean'], p)))
print('  Min: %.2f' % ntp['Average Packet Size_Mean'].min())
print('  Max: %.2f' % ntp['Average Packet Size_Mean'].max())
print()

# Sample actual packet length values to understand range
print('=== Packet Length Std raw values (sample) ===')
std_vals = ntp['Packet Length Std_Mean'].head(20).values
print('  First 20:', std_vals)
print()

print('=== Flow Duration raw values (sample) ===')
dur_vals = ntp['Flow Duration_Mean'].head(20).values
print('  First 20:', dur_vals)
print()

# What fraction of NTP flows have exactly 2 packets?
print('=== Packet count distribution ===')
print('  Flows with exactly 2 total packets: %.1f%%' % (100.0 * (ntp['Total_Packets_Mean'] == 2).sum() / len(ntp)))
print('  Flows with 2-10 total packets: %.1f%%' % (100.0 * ((ntp['Total_Packets_Mean'] >= 2) & (ntp['Total_Packets_Mean'] <= 10)).sum() / len(ntp)))
print('  Flows with 10-50 total packets: %.1f%%' % (100.0 * ((ntp['Total_Packets_Mean'] > 10) & (ntp['Total_Packets_Mean'] <= 50)).sum() / len(ntp)))
print('  Flows with 50-100 total packets: %.1f%%' % (100.0 * ((ntp['Total_Packets_Mean'] > 50) & (ntp['Total_Packets_Mean'] <= 100)).sum() / len(ntp)))
print('  Flows with >100 total packets: %.1f%%' % (100.0 * (ntp['Total_Packets_Mean'] > 100).sum() / len(ntp)))
