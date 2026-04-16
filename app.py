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
df['_is_bf_syn'] = df.apply(lambda r: syn_flags.get((r['_src_dst'], r['_time_bin']], False), axis=1)

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
