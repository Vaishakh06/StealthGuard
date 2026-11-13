import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']

ldap = df[df['Label'] == 'DrDoS_LDAP']
print('=== DrDoS_LDAP Training Statistics ===')
print('Count:', len(ldap))
print()
print('=== Total Packets Per Flow ===')
print('  Mean: %.2f' % ldap['Total_Packets_Mean'].mean())
print('  Median: %.2f' % ldap['Total_Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Total_Packets_Mean'], p)))
print('  Min: %.2f' % ldap['Total_Packets_Mean'].min())
print('  Max: %.2f' % ldap['Total_Packets_Mean'].max())
print()

print('=== Forward Packets Per Flow ===')
print('  Mean: %.2f' % ldap['Total Fwd Packets_Mean'].mean())
print('  Median: %.2f' % ldap['Total Fwd Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Total Fwd Packets_Mean'], p)))
print('  Min: %.2f' % ldap['Total Fwd Packets_Mean'].min())
print('  Max: %.2f' % ldap['Total Fwd Packets_Mean'].max())
print()

print('=== Backward Packets Per Flow ===')
print('  Mean: %.4f' % ldap['Total Backward Packets_Mean'].mean())
print('  Median: %.4f' % ldap['Total Backward Packets_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.4f' % (p, np.percentile(ldap['Total Backward Packets_Mean'], p)))
print('  Min: %.4f' % ldap['Total Backward Packets_Mean'].min())
print('  Max: %.4f' % ldap['Total Backward Packets_Mean'].max())
print()

print('=== Flow Duration (microseconds) ===')
print('  Mean: %.2f' % ldap['Flow Duration_Mean'].mean())
print('  Median: %.2f' % ldap['Flow Duration_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Flow Duration_Mean'], p)))
print('  Min: %.2f' % ldap['Flow Duration_Mean'].min())
print('  Max: %.2f' % ldap['Flow Duration_Mean'].max())
print()

print('=== Flow Bytes/s ===')
print('  Mean: %.2f' % ldap['Flow Bytes/s_Mean'].mean())
print('  Median: %.2f' % ldap['Flow Bytes/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Flow Bytes/s_Mean'], p)))
print('  Min: %.2f' % ldap['Flow Bytes/s_Mean'].min())
print('  Max: %.2f' % ldap['Flow Bytes/s_Mean'].max())
print()

print('=== Flow Packets/s ===')
print('  Mean: %.2f' % ldap['Flow Packets/s_Mean'].mean())
print('  Median: %.2f' % ldap['Flow Packets/s_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Flow Packets/s_Mean'], p)))
print('  Min: %.2f' % ldap['Flow Packets/s_Mean'].min())
print('  Max: %.2f' % ldap['Flow Packets/s_Mean'].max())
print()

print('=== Packet Length Mean ===')
print('  Mean: %.2f' % ldap['Packet Length Mean_Mean'].mean())
print('  Median: %.2f' % ldap['Packet Length Mean_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Packet Length Mean_Mean'], p)))
print('  Min: %.2f' % ldap['Packet Length Mean_Mean'].min())
print('  Max: %.2f' % ldap['Packet Length Mean_Mean'].max())
print()

print('=== Packet Length Std ===')
print('  Mean: %.2f' % ldap['Packet Length Std_Mean'].mean())
print('  Median: %.2f' % ldap['Packet Length Std_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Packet Length Std_Mean'], p)))
print('  Min: %.2f' % ldap['Packet Length Std_Mean'].min())
print('  Max: %.2f' % ldap['Packet Length Std_Mean'].max())
print()

print('=== Average Packet Size ===')
print('  Mean: %.2f' % ldap['Average Packet Size_Mean'].mean())
print('  Median: %.2f' % ldap['Average Packet Size_Mean'].median())
for p in [10, 25, 75, 90]:
    print('  P%d: %.2f' % (p, np.percentile(ldap['Average Packet Size_Mean'], p)))
print('  Min: %.2f' % ldap['Average Packet Size_Mean'].min())
print('  Max: %.2f' % ldap['Average Packet Size_Mean'].max())
print()

# Packet count distribution
print('=== Packet count distribution ===')
print('  Flows with exactly 2 total packets: %.1f%%' % (100.0 * (ldap['Total_Packets_Mean'] == 2).sum() / len(ldap)))
print('  Flows with 2-9 total packets: %.1f%%' % (100.0 * ((ldap['Total_Packets_Mean'] >= 2) & (ldap['Total_Packets_Mean'] < 10)).sum() / len(ldap)))
print('  Flows with 10-49 total packets: %.1f%%' % (100.0 * ((ldap['Total_Packets_Mean'] >= 10) & (ldap['Total_Packets_Mean'] < 50)).sum() / len(ldap)))
print('  Flows with 50-99 total packets: %.1f%%' % (100.0 * ((ldap['Total_Packets_Mean'] >= 50) & (ldap['Total_Packets_Mean'] < 100)).sum() / len(ldap)))
print('  Flows with 100+ total packets: %.1f%%' % (100.0 * (ldap['Total_Packets_Mean'] >= 100).sum() / len(ldap)))

# Backward packet presence
has_bwd = (ldap['Total Backward Packets_Mean'] > 0).sum()
print()
print('=== Backward packet presence ===')
print('  Windows with backward packets: %d/%d (%.1f%%)' % (has_bwd, len(ldap), 100.0 * has_bwd / len(ldap)))

# Packet length comparison with NTP
print()
print('=== Packet Length Comparison: DrDoS_LDAP vs DrDoS_NTP ===')
ntp = df[df['Label'] == 'DrDoS_NTP']
print('  DrDoS_LDAP pkt len mean: median=%.0f, P25=%.0f, P75=%.0f' % (
    np.median(ldap['Packet Length Mean_Mean']),
    np.percentile(ldap['Packet Length Mean_Mean'], 25),
    np.percentile(ldap['Packet Length Mean_Mean'], 75)
))
print('  DrDoS_NTP pkt len mean: median=%.0f, P25=%.0f, P75=%.0f' % (
    np.median(ntp['Packet Length Mean_Mean']),
    np.percentile(ntp['Packet Length Mean_Mean'], 25),
    np.percentile(ntp['Packet Length Mean_Mean'], 75)
))

# Rate comparison
print()
print('=== Rate Comparison: DrDoS_LDAP vs DrDoS_NTP ===')
print('  DrDoS_LDAP Flow Packets/s: median=%.0f' % np.median(ldap['Flow Packets/s_Mean']))
print('  DrDoS_NTP Flow Packets/s: median=%.0f' % np.median(ntp['Flow Packets/s_Mean']))
print('  DrDoS_LDAP Flow Bytes/s: median=%.0f' % np.median(ldap['Flow Bytes/s_Mean']))
print('  DrDoS_NTP Flow Bytes/s: median=%.0f' % np.median(ntp['Flow Bytes/s_Mean']))
