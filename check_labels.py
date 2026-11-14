import csv

csv_path = r'C:\CSBS\major_project_git\StealthGuard\dataset\engineered\engineered_dataset.csv'

# Read all unique labels from CSV
all_labels = set()

with open(csv_path, 'r') as f:
    header = f.readline()  # Skip header
    for line in f:
        parts = line.strip().split(',')
        label = parts[-1]  # Last column is Label
        all_labels.add(label)

print('All unique labels in CSV:')
for label in sorted(all_labels):
    print(f'  "{label}"')

print(f'\nTotal unique labels: {len(all_labels)}')

# Check which labels are NOT in my mapping
LABEL_MAP = {
    'BENIGN': 'BENIGN',
    'LDAP': 'BENIGN',
    'Syn': 'TCP_DDoS',
    'Portmap': 'TCP_DDoS',
    'MSSQL': 'TCP_DDoS',
    'DrDoS_MSSQL': 'TCP_DDoS',
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
}

unmapped = all_labels - set(LABEL_MAP.keys())
print(f'\nUnmapped labels: {unmapped}')
print(f'Mapped labels: {len(all_labels - unmapped)}')
print(f'Unmapped labels count: {len(unmapped)}')
