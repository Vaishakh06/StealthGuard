import pandas as pd
import numpy as np

df = pd.read_csv('C:\\CSBS\\major_project_git\\StealthGuard\\dataset\\engineered\\engineered_dataset.csv')
df['Total_Packets_Mean'] = df['Total Fwd Packets_Mean'] + df['Total Backward Packets_Mean']

# Shortlisted classes from previous analysis (F1 > 0.90)
shortlisted = ['TFTP', 'DrDoS_DNS', 'Syn', 'DrDoS_SNMP', 'DrDoS_LDAP', 'DrDoS_NTP']

print('='*80)
print('TRAINING DATA ANALYSIS - SHORTLISTED ATTACK CLASSES')
print('='*80)

for label in shortlisted:
    sub = df[df['Label'] == label]
    print()
    print(f'=== {label} ({len(sub)} windows) ===')
    print(f'  Total Packets/Flow: mean={sub["Total_Packets_Mean"].mean():.1f}, median={sub["Total_Packets_Mean"].median():.1f}, '
          f'P25={np.percentile(sub["Total_Packets_Mean"],25):.1f}, P75={np.percentile(sub["Total_Packets_Mean"],75):.1f}, '
          f'min={sub["Total_Packets_Mean"].min():.1f}, max={sub["Total_Packets_Mean"].max():.1f}')
    print(f'  Fwd Packets: mean={sub["Total Fwd Packets_Mean"].mean():.1f}, median={sub["Total Fwd Packets_Mean"].median():.1f}, '
          f'P25={np.percentile(sub["Total Fwd Packets_Mean"],25):.1f}, P75={np.percentile(sub["Total Fwd Packets_Mean"],75):.1f}')
    print(f'  Bwd Packets: mean={sub["Total Backward Packets_Mean"].mean():.4f}, median={sub["Total Backward Packets_Mean"].median():.4f}, '
          f'max={sub["Total Backward Packets_Mean"].max():.1f}')
    print(f'  Flow Duration(us): mean={sub["Flow Duration_Mean"].mean():.0f}, median={sub["Flow Duration_Mean"].median():.0f}, '
          f'P25={np.percentile(sub["Flow Duration_Mean"],25):.0f}, P75={np.percentile(sub["Flow Duration_Mean"],75):.0f}')
    print(f'  Flow Bytes/s: mean={sub["Flow Bytes/s_Mean"].mean():.0f}, median={sub["Flow Bytes/s_Mean"].median():.0f}')
    print(f'  Flow Packets/s: mean={sub["Flow Packets/s_Mean"].mean():.0f}, median={sub["Flow Packets/s_Mean"].median():.0f}')
    print(f'  Pkt Len Mean: mean={sub["Packet Length Mean_Mean"].mean():.1f}, median={sub["Packet Length Mean_Mean"].median():.1f}, '
          f'P25={np.percentile(sub["Packet Length Mean_Mean"],25):.1f}, P75={np.percentile(sub["Packet Length Mean_Mean"],75):.1f}')
    print(f'  Pkt Len Std: mean={sub["Packet Length Std_Mean"].mean():.1f}, median={sub["Packet Length Std_Mean"].median():.1f}')
    print(f'  Avg Pkt Size: mean={sub["Average Packet Size_Mean"].mean():.1f}, median={sub["Average Packet Size_Mean"].median():.1f}')
    
    # Packet count distribution
    p2 = (sub['Total_Packets_Mean'] < 2).sum()
    p10 = ((sub['Total_Packets_Mean'] >= 2) & (sub['Total_Packets_Mean'] < 10)).sum()
    p10_50 = ((sub['Total_Packets_Mean'] >= 10) & (sub['Total_Packets_Mean'] < 50)).sum()
    p50_100 = ((sub['Total_Packets_Mean'] >= 50) & (sub['Total_Packets_Mean'] < 100)).sum()
    p100 = (sub['Total_Packets_Mean'] >= 100).sum()
    print(f'  Packet count dist: <2={p2}, 2-9={p10}, 10-49={p10_50}, 50-99={p50_100}, 100+={p100}')
    
    # Backward packet presence
    has_bwd = (sub['Total Backward Packets_Mean'] > 0).sum()
    print(f'  Windows with backward packets: {has_bwd}/{len(sub)} ({100*has_bwd/len(sub):.1f}%)')
