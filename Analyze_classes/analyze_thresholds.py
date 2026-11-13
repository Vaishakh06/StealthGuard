import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']

classes = sorted(df['Label'].unique())

print('=== Impact of Different Minimum Packet Thresholds ===')
print()
print('Threshold analysis: % of windows EXCLUDED at each threshold')
print('(A window is excluded if its mean packets per flow < threshold)')
print()
print('%-18s %8s %8s %8s %8s %8s' % ('Class', 'Total', '<2pkts', '<3pkts', '<5pkts', '<10pkts'))
print('-' * 70)

threshold_impact = {}
for label in classes:
    sub = df[df['Label'] == label]
    total = len(sub)
    t2 = (sub['Total_Packets_Mean'] < 2).sum()
    t3 = (sub['Total_Packets_Mean'] < 3).sum()
    t5 = (sub['Total_Packets_Mean'] < 5).sum()
    t10 = (sub['Total_Packets_Mean'] < 10).sum()
    threshold_impact[label] = {'total': total, 't2': t2, 't3': t3, 't5': t5, 't10': t10}
    print('%-18s %8d %8.1f%% %8.1f%% %8.1f%% %8.1f%%' % (
        label, total,
        100.0 * t2 / total,
        100.0 * t3 / total,
        100.0 * t5 / total,
        100.0 * t10 / total
    ))

print()
print('=== Overall Impact ===')
total = len(df)
for t_name, t_val in [('<2', 2), ('<3', 3), ('<5', 5), ('<10', 10)]:
    excluded = (df['Total_Packets_Mean'] < t_val).sum()
    print('Threshold %s: %d/%d windows excluded (%.2f%%)' % (t_name, excluded, total, 100.0 * excluded / total))

print()
print('=== Per-Class: What % of windows have mean >= 2 packets/flow? ===')
print('(These windows would PASS a threshold of 2)')
print()
print('%-18s %10s %10s %10s' % ('Class', 'Mean≥2%', 'Mean≥3%', 'Mean≥5%'))
print('-' * 50)
for label in classes:
    sub = df[df['Label'] == label]
    p2 = 100.0 * (sub['Total_Packets_Mean'] >= 2).sum() / len(sub)
    p3 = 100.0 * (sub['Total_Packets_Mean'] >= 3).sum() / len(sub)
    p5 = 100.0 * (sub['Total_Packets_Mean'] >= 5).sum() / len(sub)
    print('%-18s %10.1f%% %10.1f%% %10.1f%%' % (label, p2, p3, p5))
