import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
print('Shape:', df.shape)
print('Label column unique values:', df['Label'].nunique())
print()

# Total packets per flow = Fwd + Bwd mean
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']
df['Min_Fwd'] = df['Total Fwd Packets_Min']
df['Min_Bwd'] = df['Total Backward Packets_Min']

print('=== Min Forward Packets per Flow (per window) ===')
print('Min:', df['Min_Fwd'].min())
print('Max:', df['Min_Fwd'].max())
print()
print('Windows where Min_Fwd == 1:', (df['Min_Fwd'] == 1).sum())
print('Windows where Min_Fwd == 0:', (df['Min_Fwd'] == 0).sum())
print()
print('=== Min Backward Packets per Flow (per window) ===')
print('Min:', df['Min_Bwd'].min())
print('Max:', df['Min_Bwd'].max())
print()
print('Windows where Min_Bwd == 1:', (df['Min_Bwd'] == 1).sum())
print('Windows where Min_Bwd == 0:', (df['Min_Bwd'] == 0).sum())
print()
print('=== Windows where BOTH Min_Fwd==1 AND Min_Bwd==1 (single-packet bidirectional flows) ===')
single_pkt = df[(df['Min_Fwd'] == 1) & (df['Min_Bwd'] == 1)]
print('Count:', len(single_pkt))
print('Percentage: %.2f%%' % (100.0 * len(single_pkt) / len(df)))
print()
print('=== Windows where Min_Fwd + Min_Bwd <= 2 (flows with at most 2 total packets) ===')
low_pkt = df[(df['Min_Fwd'] + df['Min_Bwd']) <= 2]
print('Count:', len(low_pkt))
print('Percentage: %.2f%%' % (100.0 * len(low_pkt) / len(df)))
print()
print('=== Per-Class Packet Count Statistics ===')
class_stats = {}
for label in sorted(df['Label'].unique()):
    sub = df[df['Label'] == label]
    stats = {
        'count': len(sub),
        'mean_total_pkts': sub['Total_Packets_Mean'].mean(),
        'median_total_pkts': sub['Total_Packets_Mean'].median(),
        'min_total_pkts': sub['Total_Packets_Mean'].min(),
        'max_total_pkts': sub['Total_Packets_Mean'].max(),
        'p10_total_pkts': np.percentile(sub['Total_Packets_Mean'], 10),
        'p25_total_pkts': np.percentile(sub['Total_Packets_Mean'], 25),
        'p75_total_pkts': np.percentile(sub['Total_Packets_Mean'], 75),
        'p90_total_pkts': np.percentile(sub['Total_Packets_Mean'], 90),
        'min_fwd_eq_1_pct': 100.0 * (sub['Min_Fwd'] == 1).sum() / len(sub),
        'min_bwd_eq_1_pct': 100.0 * (sub['Min_Bwd'] == 1).sum() / len(sub),
        'single_pkt_pct': 100.0 * len(sub[(sub['Min_Fwd'] == 1) & (sub['Min_Bwd'] == 1)]) / len(sub),
    }
    class_stats[label] = stats

print('%-18s %8s %10s %10s %8s %8s %8s %8s %8s %10s %10s %10s' % (
    'Class', 'Count', 'Mean', 'Median', 'Min', 'Max', 'P10', 'P25', 'P75', 'MinFwd1%', 'MinBwd1%', 'SinglePkt%'
))
for label in sorted(class_stats.keys()):
    s = class_stats[label]
    print('%-18s %8d %10.2f %10.2f %8.2f %8.2f %8.2f %8.2f %8.2f %10.2f %10.2f %10.2f' % (
        label, s['count'], s['mean_total_pkts'], s['median_total_pkts'], s['min_total_pkts'],
        s['max_total_pkts'], s['p10_total_pkts'], s['p25_total_pkts'], s['p75_total_pkts'],
        s['min_fwd_eq_1_pct'], s['min_bwd_eq_1_pct'], s['single_pkt_pct']
    ))
