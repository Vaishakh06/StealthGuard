import csv
import os

csv_path = r'C:\CSBS\major_project_git\StealthGuard\dataset\engineered\engineered_dataset.csv'
output_path = r'C:\CSBS\major_project_git\StealthGuard\dataset\engineered\engineered_3class.csv'

LABEL_MAP = {
    # BENIGN class
    'BENIGN': 'BENIGN',
    'LDAP': 'BENIGN',
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
}

chunk_size = 100000
total_rows = 0
label_counts = {'BENIGN': 0, 'TCP_DDoS': 0, 'UDP_DDoS': 0}

with open(csv_path, 'r') as f:
    header = f.readline()  # Skip header

with open(output_path, 'w') as out_f:
    out_f.write(header)

    with open(csv_path, 'r') as f:
        header = f.readline()  # Skip header
        
        for line in f:
            parts = line.strip().split(',')
            label = parts[-1]
            
            if label in LABEL_MAP:
                new_label = LABEL_MAP[label]
                parts[-1] = new_label
                out_f.write(','.join(parts) + '\n')
                
                label_counts[new_label] += 1
            else:
                print(f"WARNING: Unmapped label: '{label}'")
            
            total_rows += 1
            
            if total_rows % 500000 == 0:
                print(f'Processed {total_rows:,} rows... Current counts: {label_counts}')

print(f'\nTotal rows processed: {total_rows:,}')
print(f'Final label counts: {label_counts}')
print(f'Output saved to: {output_path}')
print(f'Output file size: {os.path.getsize(output_path) / (1024**3):.2f} GB')

# Verify all rows were mapped
total_mapped = sum(label_counts.values())
if total_mapped == total_rows:
    print(f'✓ All {total_rows:,} rows mapped successfully')
else:
    print(f'✗ MISMATCH: {total_rows} rows processed but only {total_mapped} mapped ({total_rows - total_mapped} unmapped)')
