import pandas as pd
import numpy as np

def detect_dos(df, threshold=1000):
    """Detection 1: Denial of Service (DoS)"""
    ip_traffic = df['source'].value_counts().reset_index()
    ip_traffic.columns = ['source', 'count']
    dos_ips = ip_traffic[ip_traffic['count'] > threshold]
    print('Possible DoS Attackers:\n', dos_ips)
    return dos_ips

def detect_port_scanning(df, threshold=50):
    """Detection 2: Port Scanning"""
    port_access = df.groupby('source')['destination'].nunique().reset_index()
    port_access.columns = ['source', 'unique_destinations']
    scan_ips = port_access[port_access['unique_destinations'] > threshold]
    print('\nPossible Port Scanners:\n', scan_ips)
    return scan_ips

def detect_rare_protocols(df, common_protocols=['TCP', 'UDP', 'ICMP', 'ARP']):
    """Detection 3: Rare Protocols"""
    rare_protocols = df[~df['protocol'].isin(common_protocols)]
    print('\nEntries with Rare Protocols:\n', rare_protocols.head(390000))
    print("Packets with Rare Protocols:\n", rare_protocols['protocol'].value_counts())
    return rare_protocols

def detect_data_exfiltration(df, threshold_bytes=10*1024*1024):
    """Detection 4: Large Outbound Transfers / Data Exfiltration"""
    bytes_by_source = df.groupby('source')['length'].sum().reset_index()
    bytes_by_source.columns = ['source', 'total_bytes']

    packets_by_source = df['source'].value_counts().reset_index()
    packets_by_source.columns = ['source', 'packet_count']

    bandwidth_stats = bytes_by_source.merge(packets_by_source, on='source', how='left')
    bandwidth_stats['avg_packet_size'] = bandwidth_stats['total_bytes'] / bandwidth_stats['packet_count']

    detection_large_transfers = bandwidth_stats[
        (bandwidth_stats['total_bytes'] > threshold_bytes) |
        ((bandwidth_stats['avg_packet_size'] > 1000) & (bandwidth_stats['packet_count'] > 100))
    ]
    print('\nDetection 4 - Possible Large Outbound Transfers / Data Exfiltration:\n', detection_large_transfers)
    return detection_large_transfers

def detect_broadcast_traffic(df):
    """Detect broadcast traffic"""
    broadcast_traffic = df[df['destination'].str.contains("broadcast", case=False, na=False)]
    print("Broadcast Packets Count:", len(broadcast_traffic))
    return broadcast_traffic

def run_all_detections(df):
    """Run all detections and return results"""
    dos_ips = detect_dos(df)
    scan_ips = detect_port_scanning(df)
    rare_protocols = detect_rare_protocols(df)
    large_transfers = detect_data_exfiltration(df)
    
    print('\nSuspicious IP Summary:')
    print('DoS IPs:', list(dos_ips['source'].values) if len(dos_ips) > 0 else "None")
    print('Port Scanners:', list(scan_ips['source'].values) if len(scan_ips) > 0 else "None")
    print('Rare Protocol Records:', len(rare_protocols))
    
    return {
        'dos': dos_ips,
        'port_scan': scan_ips,
        'rare_protocols': rare_protocols,
        'data_exfiltration': large_transfers
    }
