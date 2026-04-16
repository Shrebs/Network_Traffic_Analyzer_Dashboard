import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# 1. Load your CSV
df = pd.read_csv('Midterm_53_group.csv')
print(df.head(10))

# 2. FIX COLUMN NAMES (put this RIGHT AFTER loading the CSV)
df.columns = df.columns.str.strip().str.lower()

df = df.rename(columns={
    "Time": "time",
    "source": "Source",
    "destination": "Destination",
    "protocol": "Protocol",
    "length": "Length"
})


df['Length'] = pd.to_numeric(df['Length'], errors='coerce').fillna(0)
df['time_bucket'] = (df['time'] // 5) * 5


# 3. Remove unnecessary columns
if "no." in df.columns:
    df = df.drop(columns=["no."])

# 4. Confirm the cleaned CSV
print("\n✅ After cleaning column names:")
print(df.head(10))
print(df.columns)




print("Original Shape:", df.shape)
print("\n--- Columns ---")
print(df.columns)

df.info()

df.isnull().sum()



#Handles both numerical and categorical values
for col in df.columns:
    if df[col].dtype in ['int64', 'float64']:
        df[col] = pd.to_numeric(df[col], errors='coerce')
        df[col] = df[col].fillna(df[col].mean())
    else:
        df[col] = df[col].fillna(df[col].mode()[0])
        
df.drop_duplicates(inplace=True)


# Clean text columns (generic)
for col in df.select_dtypes(include=['object']).columns:
    if col not in ['Protocol', 'No.']:  # Keep these untouched
        df[col] = df[col].astype(str)
        df[col] = df[col].str.strip()
        df[col] = df[col].str.replace(r'[^A-Za-z0-9\s]', '', regex=True)
        df[col] = df[col].str.lower()
        
        df.replace(['nan', 'unknown', 'n/a'], np.nan, inplace=True)
        
        
 df.replace(['nan', 'unknown', 'n/a'], np.nan, inplace=True)
 
 #fills missing values using neighboring rows:
df['Destination'] = df['Destination'].ffill()  # forward fill
df['info'] = df['info'].bfill()                # backward fill


print("\nCleaned Dataset Sample:\n")
print(df.head(10))       


df.to_csv("NTA_Dataset_Cleaned.csv", index=False)
print("\nCleaned file saved as 'NTA_Dataset_Cleaned.csv'")



df = pd.read_csv('NTA_Dataset_Cleaned.csv')
print(df.head(20))



#Detection 1 : DoS
ip_traffic = df['Source'].value_counts().reset_index()
ip_traffic.columns = ['Source', 'Count']
dos_ips = ip_traffic[ip_traffic['Count'] > 1000]
print('Possible DoS Attackers:\n', dos_ips)




#Detection 2 : port scanning
port_access = df.groupby('Source')['Destination'].nunique().reset_index()
port_access.columns = ['Source', 'Unique_Destinations']
scan_ips = port_access[port_access['Unique_Destinations'] > 50]
print('\nPossible Port Scanners:\n', scan_ips)




#Detection 3 : rare protocols
common_protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
rare_protocols = df[~df['Protocol'].isin(common_protocols)]
print('\nEntries with Rare Protocols:\n', rare_protocols.head(390000))





common_protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
rare_protocols = df[~df['Protocol'].isin(common_protocols)]
print("Packets with Rare Protocols:\n", rare_protocols['Protocol'].value_counts())




#Detection 4
bytes_by_source = df.groupby('Source')['Length'].sum().reset_index()
bytes_by_source.columns = ['Source', 'Total_Bytes']

packets_by_source = df['Source'].value_counts().reset_index()
packets_by_source.columns = ['Source', 'Packet_Count']

bandwidth_stats = bytes_by_source.merge(packets_by_source, on='Source', how='left')
bandwidth_stats['Avg_Packet_Size'] = bandwidth_stats['Total_Bytes'] / bandwidth_stats['Packet_Count']

threshold_bytes = 10 * 1024 * 1024  # 10 MB
detection_5_large_transfers = bandwidth_stats[
    (bandwidth_stats['Total_Bytes'] > threshold_bytes) |
    ((bandwidth_stats['Avg_Packet_Size'] > 1000) & (bandwidth_stats['Packet_Count'] > 100))
]
print('\nDetection 4 - Possible Large Outbound Transfers / Data Exfiltration:\n', detection_5_large_transfers)







# Combine and Display Results
print('Suspicious IP Summary:')
print('DoS IPs:', list(dos_ips.Source))
print('Port Scanners:', list(scan_ips.Source))
print('Rare Protocol Records:', len(rare_protocols))




broadcast_traffic = df[df['Destination'].str.contains("broadcast", case=False, na=False)]
print("Broadcast Packets Count:", len(broadcast_traffic))



df["packet_count"] = 1


# Ensure 'Length' is numeric and handle potential NaN values
df['Length'] = pd.to_numeric(df['Length'], errors='coerce')
df['Length'] = df['Length'].fillna(df['Length'].mean()) # Fill NaN with mean after coercion

total_packets = int(df['packet_count'].sum())
total_data_transferred = int(df['Length'].sum())
unique_source_ips = df['Source'].nunique()
unique_destination_ips = df['Destination'].nunique()
most_used_protocol = df['Protocol'].mode().iloc[0] if not df['Protocol'].mode().empty else None

# Peak hour calculation (safe guarding against missing times and ensuring datetime format)
if 'Time' in df.columns and df['Time'].notna().any():
    # Ensure 'Time' is datetime before extracting hour
    df['Time_datetime'] = pd.to_datetime(df['Time'], unit='s', errors='coerce')
    if df['Time_datetime'].notna().any():
        peak_hour_index = df.groupby(df['Time_datetime'].dt.hour)['packet_count'].sum().idxmax()
        peak_hour_counts = int(df.groupby(df['Time_datetime'].dt.hour)['packet_count'].sum().max())
        peak_hour_str = f"{peak_hour_index}:00 ({peak_hour_counts} packets)"
    else:
        peak_hour_str = "N/A (no valid time data)"
else:
    peak_hour_str = "N/A (Time column not available or empty)"


print("\nDASHBOARD KPIs")
print(f"Total Packets Captured       : {total_packets}")
print(f"Total Data Transferred (B)   : {total_data_transferred}")
print(f"Unique Source IPs            : {unique_source_ips}")
print(f"Unique Destination IPs       : {unique_destination_ips}")
print(f"Most Used Protocol           : {most_used_protocol}")
print(f"Peak Traffic Hour (UTC)      : {peak_hour_str}")







# Streamlit — write app.py
%%writefile app.py
!pip install streamlit pyngrok plotly

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

st.set_page_config(layout="wide", page_title="NTA Dashboard - 4 Detections")

st.title("Network Traffic Analysis Dashboard")
st.markdown("Upload your raw CSV (columns like Time, Source, Destination, Protocol, Length, Flags, AuthResult)")

uploaded = st.file_uploader("Upload CSV", type=["csv"])
if not uploaded:
    st.info("Upload a CSV file to start.")
    st.stop()

# --- read file ---
df = pd.read_csv(uploaded)
df.columns = df.columns.str.strip().str.lower()

# Map to standard columns
col_map = {}
cset = set(df.columns)
def find(cols):
    for v in cols:
        if v in cset:
            return v
    return None

col_map['time'] = find(['time','timestamp','frame.time_epoch','ts','frame.time'])
col_map['source'] = find(['source','src','ip.src'])
col_map['destination'] = find(['destination','dst','ip.dst'])
col_map['protocol'] = find(['protocol','proto'])
col_map['length'] = find(['length','len','frame.len','packet_length'])
col_map['flags'] = find(['flags','tcp_flags','flag'])
col_map['auth'] = find(['auth','login','status','result','response'])

required_found = all([col_map['time'], col_map['source'], col_map['destination'], col_map['protocol'], col_map['length']])
if not required_found:
    st.error("CSV missing required fields. Detected columns: " + ", ".join(df.columns))
    st.stop()

df = df.rename(columns={col_map[k]: k for k in col_map if col_map[k]})

# ensure numeric types
df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0)
try:
    df['time'] = pd.to_numeric(df['time'], errors='coerce')
except Exception:
    pass
df['time'] = df['time'].fillna(0)

# normalize protocol to uppercase
df['protocol'] = df['protocol'].astype(str).str.upper()

# time bucket
window = st.sidebar.number_input("Time window (seconds)", value=60, min_value=1)
df['_time_bin'] = (df['time'] // int(window)) * int(window)

# --- Detection rules ---

# 1) DoS
df['_src_dst'] = df['source'].astype(str) + "###" + df['destination'].astype(str)
dos_agg = df.groupby(['_src_dst', '_time_bin']).agg(pkt_count=('_src_dst','size'), total_bytes=('length','sum')).reset_index()
dos_pkt_th = st.sidebar.number_input("DoS: packet count threshold", value=100, min_value=1)
dos_bytes_th = st.sidebar.number_input("DoS: bytes threshold", value=1000000, min_value=1)
dos_agg['is_dos_bin'] = (dos_agg['pkt_count'] >= dos_pkt_th) | (dos_agg['total_bytes'] >= dos_bytes_th)
dos_flags = dos_agg.set_index(['_src_dst','_time_bin'])['is_dos_bin'].to_dict()
df['_is_dos_bin'] = df.apply(lambda r: dos_flags.get((r['_src_dst'], r['_time_bin']), False), axis=1)

# 2) Port scan
portscan_agg = df.groupby(['source','_time_bin'])['destination'].nunique().reset_index(name='unique_dests')
ps_ports_th = st.sidebar.number_input("PortScan: unique dest threshold", value=50, min_value=1)
portscan_agg['is_portscan_bin'] = portscan_agg['unique_dests'] >= ps_ports_th
ps_flags = portscan_agg.set_index(['source','_time_bin'])['is_portscan_bin'].to_dict()
df['_is_portscan_bin'] = df.apply(lambda r: ps_flags.get((r['source'], r['_time_bin']), False), axis=1)

# 3) Brute Force (internal only)
df['_auth_fail'] = False
if col_map.get('auth'):
    auth_col = 'auth'
    df['_auth_fail'] = df[auth_col].astype(str).str.lower().isin(['fail','failed','failure','0','false','no','denied','unsuccessful','invalid'])
bf_fail_th = st.sidebar.number_input("BruteForce: failed auths threshold (internal)", value=10, min_value=1)
auth_agg = df.groupby(['source','destination','_time_bin'])['_auth_fail'].sum().reset_index(name='failed_auths')
auth_agg['is_bf_auth'] = auth_agg['failed_auths'] >= bf_fail_th
auth_flags = auth_agg.set_index(['source','destination','_time_bin'])['is_bf_auth'].to_dict()
df['_is_bf_auth'] = df.apply(lambda r: auth_flags.get((r['source'], r['destination'], r['_time_bin']), False), axis=1)

# SYN heuristic (internal only)
df['_is_syn'] = False
df['_is_ack'] = False
if col_map.get('flags') and col_map['flags'] in df.columns:
    flags_col = 'flags'
    df['_is_syn'] = df[flags_col].astype(str).str.contains('SYN', case=False, na=False)
    df['_is_ack'] = df[flags_col].astype(str).str.contains('ACK', case=False, na=False)
syn_th = st.sidebar.number_input("BruteForce: SYN-only threshold (internal)", value=50, min_value=1)
syn_agg = df.groupby(['_src_dst','_time_bin']).agg(syn_count=('_is_syn','sum'), ack_count=('_is_ack','sum')).reset_index()
syn_agg['syn_only'] = (syn_agg['syn_count'] >= syn_th) & (syn_agg['ack_count'] <= (syn_agg['syn_count']*0.2))
syn_flags = syn_agg.set_index(['_src_dst','_time_bin'])['syn_only'].to_dict()
df['_is_bf_syn'] = df.apply(lambda r: syn_flags.get((r['_src_dst'], r['_time_bin']), False), axis=1)

# 4) Rare Protocol
common_protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
df['_is_rare_protocol'] = ~df['protocol'].isin(common_protocols)
df['_is_rare_protocol'] = df['_is_rare_protocol'] & (df['protocol'].str.len() > 0)

# 5) Data Exfiltration
bytes_by_source = df.groupby('source')['length'].sum().reset_index()
bytes_by_source.columns = ['source','total_bytes']
packets_by_source = df['source'].value_counts().reset_index()
packets_by_source.columns = ['source','packet_count']
bandwidth_stats = bytes_by_source.merge(packets_by_source, on='source', how='left')
bandwidth_stats['avg_pkt_size'] = bandwidth_stats['total_bytes'] / bandwidth_stats['packet_count']
threshold_bytes = 10*1024*1024
threshold_avg_pkt_size = 1000
threshold_pkt_count = 100
large_transfer_sources = bandwidth_stats[(bandwidth_stats['total_bytes']>threshold_bytes) |
                                         ((bandwidth_stats['avg_pkt_size']>threshold_avg_pkt_size)&(bandwidth_stats['packet_count']>threshold_pkt_count))]['source'].tolist()
df['_is_large_transfer'] = df['source'].isin(large_transfer_sources)

df['_is_bruteforce'] = df['_is_bf_auth'] | df['_is_bf_syn']

# FIXED — use Normal but remove it later
def pick_label(r):
    if r.get('_is_dos_bin', False): return "Detection 1 : DoS"
    if r.get('_is_portscan_bin', False): return "Detection 2 : Port Scan"
    if r.get('_is_rare_protocol', False): return "Detection 3 : Rare Protocol"
    if r.get('_is_large_transfer', False): return "Detection 4 : Data Exfil"
    return "Normal"

df['Attack'] = df.apply(pick_label, axis=1)

# Quick stats
st.sidebar.markdown("### Quick stats")
st.sidebar.write(f"Rows: {len(df):,}")
st.sidebar.write(df['Attack'].value_counts().to_dict())

# FIXED — remove Normal before charts
attack_counts = df['Attack'].value_counts()
attack_counts = attack_counts[attack_counts.index != "Normal"]

selected = st.selectbox("Filter by Detection Type", ["All"] + list(attack_counts.index))
filtered = df if selected == "All" else df[df['Attack'] == selected]

# ---------- LAYOUT: 3x2 grid ----------
col1, col2 = st.columns(2)
col3, col4 = st.columns(2)
col5, col6 = st.columns(2)

# FIXED PIE CHART
with col1:
    st.subheader("Detection Distribution (All)")
    fig = px.pie(names=attack_counts.index, values=attack_counts.values, hole=0.35,
                 color_discrete_sequence=px.colors.qualitative.Pastel)
    fig.update_traces(textinfo='percent+label')
    fig.update_layout(height=320, margin=dict(t=40,b=0,l=0,r=0))
    st.plotly_chart(fig, use_container_width=True)

# BAR: Top source
with col2:
    st.subheader("Top 10 Source IPs (Filtered)")
    top_src = filtered.groupby('source')['length'].sum().sort_values(ascending=False).head(10)
    if not top_src.empty:
        df_top_src = top_src.reset_index()
        df_top_src.columns = ['source','total_bytes']
        fig_s = px.bar(df_top_src, x='total_bytes', y='source', orientation='h', height=320,
                       color='total_bytes', color_continuous_scale='Blues')
        st.plotly_chart(fig_s, use_container_width=True)
    else: st.info("No source data")

# Protocol pie
with col3:
    st.subheader("Protocol Distribution (Filtered)")
    proto_counts = filtered['protocol'].value_counts()
    figp = px.pie(names=proto_counts.index, values=proto_counts.values, hole=0.35,
                  color_discrete_sequence=["#ffb703","#fb8500","#8ecae6","#219ebc","#023047"])
    figp.update_traces(textinfo='percent+label')
    figp.update_layout(height=320, margin=dict(t=40,b=0,l=0,r=0))
    st.plotly_chart(figp, use_container_width=True)

# Destinations
with col4:
    st.subheader("Top 10 Destination IPs (Filtered)")
    top_dst = filtered.groupby('destination')['length'].sum().sort_values(ascending=False).head(10)
    if not top_dst.empty:
        df_top_dst = top_dst.reset_index()
        df_top_dst.columns = ['destination','total_bytes']
        fig_d = px.bar(df_top_dst, x='total_bytes', y='destination', orientation='h', height=320,
                       color='total_bytes', color_continuous_scale='Plasma')
        st.plotly_chart(fig_d, use_container_width=True)
    else: st.info("No destination data")

# Line chart
with col5:
    st.subheader("Traffic over Time with Detected Anomalies")
    traffic_time = df.groupby('_time_bin')['length'].sum().reset_index()
    traffic_time['anomaly'] = df.groupby('_time_bin')['_is_dos_bin'].max().values
    fig_line = px.line(traffic_time, x='_time_bin', y='length', title='Traffic Volume Over Time')
    fig_line.add_scatter(x=traffic_time['_time_bin'][traffic_time['anomaly']],
                         y=traffic_time['length'][traffic_time['anomaly']],
                         mode='markers', marker=dict(color='red', size=10), name='Anomaly')
    st.plotly_chart(fig_line, use_container_width=True)

# Packet categories
with col6:
    st.subheader("Traffic Classification (Packet Size)")
    bins = [0, 200, 500, 1000, 1500, np.inf]
    labels = ['Tiny','Small','Medium','Large','Huge']
    filtered['pkt_category'] = pd.cut(filtered['length'], bins=bins, labels=labels)
    category_counts = filtered['pkt_category'].value_counts().sort_index()
    fig_cat = px.bar(category_counts, x=category_counts.index, y=category_counts.values,
                     color=category_counts.values, color_continuous_scale='Viridis', labels={'y':'Count'})
    st.plotly_chart(fig_cat, use_container_width=True)

# Summary table
st.markdown("---")
st.subheader("📘 Filter-Based Summary Table")

def compute_summary(data):
    if data.empty:
        return pd.DataFrame([
            {"Attribute": "No Data", "Value": "-", "Notes / Description":
             "The current filter returned no rows."}
        ])

    src_bytes = data.groupby('source')['length'].sum().sort_values(ascending=False)
    top_source = src_bytes.index[0] if not src_bytes.empty else "-"

    dst_bytes = data.groupby('destination')['length'].sum().sort_values(ascending=False)
    top_destination = dst_bytes.index[0] if not dst_bytes.empty else "-"

    top_protocol = data['protocol'].mode()[0] if not data['protocol'].empty else "-"

    peak_bin = data['_time_bin'].mode()[0] if '_time_bin' in data.columns and not data['_time_bin'].empty else "-"

    return pd.DataFrame([
        {
            "Attribute": "Top Source IP (by bytes)",
            "Value": top_source,
            "Notes / Description": "This IP sent the highest traffic volume — possible source of large transfers"
        },
        {
            "Attribute": "Top Destination IP (by bytes)",
            "Value": top_destination,
            "Notes / Description": "This IP received the highest traffic volume — possible target or server"
        },
        {
            "Attribute": "Most Used Protocol",
            "Value": top_protocol,
            "Notes / Description": "Most frequent protocol observed"
        },
        {
            "Attribute": "Total DoS Events",
            "Value": int((data['Attack']=="Detection 1 : DoS").sum()),
            "Notes / Description": "Detected DoS events in filtered data"
        },
        {
            "Attribute": "Total Port Scan Events",
            "Value": int((data['Attack']=="Detection 2 : Port Scan").sum()),
            "Notes / Description": "Port Scan detections"
        },
        {
            "Attribute": "Total Rare Protocol Events",
            "Value": int((data['Attack']=="Detection 3 : Rare Protocol").sum()),
            "Notes / Description": "Events flagged with uncommon protocol types"
        },
        {
            "Attribute": "Total Data Exfiltration Events",
            "Value": int((data['Attack']=="Detection 4 : Data Exfil").sum()),
            "Notes / Description": "Large outbound transfers"
        },
        {
            "Attribute": "Peak Traffic Time Bin",
            "Value": peak_bin,
            "Notes / Description": f"Time interval (bucket size = {int(window)}s) with maximum byte volume"
        }
    ])

summary_table = compute_summary(filtered)
st.dataframe(summary_table, use_container_width=True)

# Download labeled CSV
csv_bytes = df.to_csv(index=False).encode('utf-8')
st.download_button("Download labeled CSV", data=csv_bytes,
                   file_name="labeled_network_data.csv", mime="text/csv")




# Install streamlit and pyngrok
!pip install --upgrade --quiet streamlit pyngrok


# Start ngrok tunnel via pyngrok (run as python cell)
from pyngrok import ngrok, conf
import time
# Put your token here:
NGROK_AUTH_TOKEN = "YOUR_NGROK_AUTH_TOKEN_HERE"
# Set auth token
conf.get_default().auth_token = NGROK_AUTH_TOKEN

# Kill any existing tunnels
try:
    ngrok.kill()  # stops previous tunnels started by pyngrok in this process
except Exception:
    pass

# Open HTTP tunnel on port 8501
public_url = ngrok.connect(addr="8501", proto="http")
print("Public URL ->", public_url)
# Optional: print full tunnel info
print(ngrok.get_tunnels())




!pkill -f ngrok



!pkill -f streamlit
!streamlit run app.py --server.port 8501 &>/content/streamlit.log &

