import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']

# Compare DNS and NTP training distributions for key features
dns = df[df['Label'] == 'DrDoS_DNS']
ntp = df[df['Label'] == 'DrDoS_NTP']

features_to_compare = [
    'Total Fwd Packets_Mean',
    'Total Backward Packets_Mean',
    'Packet Length Mean_Mean',
    'Packet Length Std_Mean',
    'Average Packet Size_Mean',
    'Flow Duration_Mean',
    'Flow Bytes/s_Mean',
    'Flow Packets/s_Mean',
]

print('=== DNS vs NTP Training Feature Comparison ===')
print()
print('%-35s %15s %15s %15s' % ('Feature', 'DNS Median', 'NTP Median', 'DNS Mean'))
print('-' * 80)
for feat in features_to_compare:
    dns_med = np.median(dns[feat])
    ntp_med = np.median(ntp[feat])
    dns_mean = dns[feat].mean()
    print('%-35s %15.2f %15.2f %15.2f' % (feat, dns_med, ntp_med, dns_mean))

print()
print('=== Packet count distribution ===')
print('DNS:  P25=%d, Median=%d, P75=%d, Mean=%.1f' % (
    np.percentile(dns['Total_Packets_Mean'], 25),
    np.median(dns['Total_Packets_Mean']),
    np.percentile(dns['Total_Packets_Mean'], 75),
    dns['Total_Packets_Mean'].mean()
))
print('NTP:  P25=%d, Median=%d, P75=%d, Mean=%.1f' % (
    np.percentile(ntp['Total_Packets_Mean'], 25),
    np.median(ntp['Total_Packets_Mean']),
    np.percentile(ntp['Total_Packets_Mean'], 75),
    ntp['Total_Packets_Mean'].mean()
))

print()
print('=== What % of DNS training flows have exactly 2 packets? ===')
print('  %.1f%%' % (100.0 * (dns['Total_Packets_Mean'] == 2).sum() / len(dns)))
print('=== What % of NTP training flows have exactly 2 packets? ===')
print('  %.1f%%' % (100.0 * (ntp['Total_Packets_Mean'] == 2).sum() / len(ntp)))

print()
print('=== Live DNS (2 packets, ~1375 bytes, ~10us duration) estimated features ===')
print('  Total Fwd Packets: 2')
print('  Total Backward Packets: 0')
print('  Packet Length Mean: ~1375')
print('  Average Packet Size: ~1375')
print('  Flow Duration: ~10 us')
print('  Flow Packets/s: ~200,000')
print('  Flow Bytes/s: ~275,000,000')
print()
print('=== Comparison: which training class is live DNS closer to? ===')
print('  Packet Length Mean: Live ~1375 -> DNS median %.0f, NTP median %.0f' % (
    np.median(dns['Packet Length Mean_Mean']),
    np.median(ntp['Packet Length Mean_Mean'])
))
print('  Total Fwd Packets: Live 2 -> DNS median %.0f, NTP median %.0f' % (
    np.median(dns['Total Fwd Packets_Mean']),
    np.median(ntp['Total Fwd Packets_Mean'])
))
print('  Flow Packets/s: Live ~200K -> DNS median %.0f, NTP median %.0f' % (
    np.median(dns['Flow Packets/s_Mean']),
    np.median(ntp['Flow Packets/s_Mean'])
))
print('  Flow Bytes/s: Live ~275M -> DNS median %.0f, NTP median %.0f' % (
    np.median(dns['Flow Bytes/s_Mean']),
    np.median(ntp['Flow Bytes/s_Mean'])
))
