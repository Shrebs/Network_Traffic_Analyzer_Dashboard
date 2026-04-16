import pandas as pd
import numpy as np

def calculate_kpis(df):
    """Calculate Dashboard KPIs"""
    df["packet_count"] = 1
    df['length'] = pd.to_numeric(df['length'], errors='coerce')
    df['length'] = df['length'].fillna(df['length'].mean())

    total_packets = int(df['packet_count'].sum())
    total_data_transferred = int(df['length'].sum())
    unique_source_ips = df['source'].nunique()
    unique_destination_ips = df['destination'].nunique()
    most_used_protocol = df['protocol'].mode().iloc[0] if not df['protocol'].mode().empty else None

    # Peak hour calculation
    peak_hour_str = "N/A"
    if 'time' in df.columns and df['time'].notna().any():
        try:
            df['time_datetime'] = pd.to_datetime(df['time'], unit='s', errors='coerce')
            if df['time_datetime'].notna().any():
                peak_hour_index = df.groupby(df['time_datetime'].dt.hour)['packet_count'].sum().idxmax()
                peak_hour_counts = int(df.groupby(df['time_datetime'].dt.hour)['packet_count'].sum().max())
                peak_hour_str = f"{peak_hour_index}:00 ({peak_hour_counts} packets)"
        except:
            peak_hour_str = "N/A"

    kpis = {
        'Total Packets Captured': total_packets,
        'Total Data Transferred (B)': total_data_transferred,
        'Unique Source IPs': unique_source_ips,
        'Unique Destination IPs': unique_destination_ips,
        'Most Used Protocol': most_used_protocol,
        'Peak Traffic Hour (UTC)': peak_hour_str
    }

    print("\n📊 DASHBOARD KPIs")
    for key, value in kpis.items():
        print(f"{key:30} : {value}")

    return kpis

def print_kpis(kpis):
    """Print KPIs nicely"""
    print("\n📊 DASHBOARD KPIs")
    for key, value in kpis.items():
        print(f"{key:30} : {value}")
