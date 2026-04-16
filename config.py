# Configuration file for NTA Project

# Thresholds for Detection
DOS_THRESHOLD = 1000
PORT_SCAN_THRESHOLD = 50
BRUTE_FORCE_FAIL_AUTH_THRESHOLD = 10
DATA_EXFIL_BYTES_THRESHOLD = 10 * 1024 * 1024  # 10 MB

# Common Protocols
COMMON_PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'ARP']

# File paths
INPUT_CSV_PATH = 'Midterm_53_group.csv'
OUTPUT_CSV_PATH = 'NTA_Dataset_Cleaned.csv'

# Dashboard settings
DASHBOARD_TITLE = "Network Traffic Analysis Dashboard"
LAYOUT = "wide"
