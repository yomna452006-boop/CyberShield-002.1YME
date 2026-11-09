import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")

NAVY, PANEL, GOLD, IVORY = "#0B111B", "#121D2B", "#C9A96A", "#F3F1EB"
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Playfair+Display:wght@500;600;700&display=swap');
.stApp{{background:{NAVY};color:{IVORY}}}
[data-testid="stHeader"]{{background:rgba(11,17,27,.96)}}
[data-testid="stSidebar"]{{background:#101925;border-right:1px solid rgba(201,169,106,.24)}}
h1,h2,h3{{font-family:'Playfair Display',Georgia,serif!important;color:{IVORY}!important}}
[data-testid="stMetric"]{{background:{PANEL};border:1px solid rgba(201,169,106,.28);padding:16px;border-radius:13px}}
[data-testid="stMetricLabel"] p{{color:#C4CCD6!important}}
[data-testid="stMetricValue"]{{color:{IVORY}!important}}
div.stButton>button,div.stDownloadButton>button{{background:{GOLD};color:#101722;border:0;border-radius:8px;font-weight:700}}
div.stButton>button:hover,div.stDownloadButton>button:hover{{background:#E0C38C;color:#101722}}
[data-testid="stDataFrame"]{{border:1px solid rgba(201,169,106,.2);border-radius:10px}}
.cs-sub{{color:#AAB5C2;font-size:1rem}}
</style>
""", unsafe_allow_html=True)

SAMPLE = pd.DataFrame([
 ["2026-11-08 09:00:00","192.168.1.10","login_success",0,1200,443],
 ["2026-11-08 09:02:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:03:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:04:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:05:00","192.168.1.15","login_failed",1,500,443],
 ["2026-11-08 09:10:00","192.168.1.22","data_transfer",0,8500000,443],
 ["2026-11-08 09:12:00","192.168.1.30","port_connection",0,800,3389],
 ["2026-11-08 09:15:00","192.168.1.10","login_success",0,1000,443],
 ["2026-11-08 09:17:00","192.168.1.42","dns_request",0,300,53],
], columns=["timestamp","source_ip","event_type","failed_logins","bytes_out","destination_port"])

def analyse(raw, window):
    required = ["timestamp","source_ip","event_type"]
    missing = [c for c in required if c not in raw.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    df = raw.copy()
    for col in ["failed_logins","bytes_out","destination_port"]:
        if col not in df: df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("Invalid timestamp. Example: 2026-11-08 09:00:00")
    df["source_ip"] = df["source_ip"].fillna("Unknown").astype(str).str.strip()
    df["event_type"] = df["event_type"].fillna("unknown").astype(str).str.lower().str.strip()
    df = df.sort_values(["source_ip","timestamp"]).reset_index(drop=True)

    # Correlation groups: consecutive events from one source within the chosen time window.
    df["incident_id"] = ""
    for ip, indexes in df.groupby("source_ip").groups.items():
        previous, group_no = None, 0
        for idx in indexes:
            current = df.at[idx,"timestamp"]
            if previous is None or (current-previous).total_seconds() > window*60:
                group_no += 1
            df.at[idx,"incident_id"] = f"{ip}-INC-{group_no:03d}"
            previous = current

    # Rolling failed-login count for each source IP.
    df["failed_attempts_window"] = 0
    for ip, indexes in df.groupby("source_ip").groups.items():
        rows = df.loc[list(indexes)].sort_values("timestamp")
        failed = rows.loc[rows.event_type.str.contains("failed"),"timestamp"].tolist()
        for idx,row in rows.iterrows():
            start = row.timestamp-pd.Timedelta(minutes=window)
            df.at[idx,"failed_attempts_window"] = sum(start <= t <= row.timestamp for t in failed)

    scores, reasons = [], []
    for _,r in df.iterrows():
        score, why = 0, []
        n = int(r.failed_attempts_window)
        if n >= 5: score += 60; why.append(f"{n} failed logins in {window} minutes")
        elif n >= 3: score += 35; why.append(f"{n} failed logins in {window} minutes")
        elif n == 2: score += 15; why.append("Repeated failed-login activity")
        if r.bytes_out >= 5_000_000: score += 35; why.append("Outbound data volume at least 5 MB")
        elif r.bytes_out >= 1_000_000: score += 20; why.append("Elevated outbound data volume")
        port = int(r.destination_port)
        if port in [23,3389,4444]: score += 15; why.append(f"Destination port {port} needs contextual review")
        if "failed" in r.event_type and n < 2: score += 5; why.append("Failed action recorded")
        scores.append(min(score,100))
        reasons.append("; ".join(why) if why else "No configured rule triggered")
    df["risk_score"] = scores
    df["risk_level"] = df.risk_score.map(lambda x: "High" if x>=60 else "Medium" if x>=30 else "Low")
    df["reason"] = reasons
    return df.sort_values("timestamp").reset_index(drop=True)

def make_incidents(events):
    output = []
    for incident_id,g in events.groupby("incident_id"):
        failed = int(g.event_type.str.contains("failed").sum())
        max_bytes = int(g.bytes_out.max())
        ports = sorted({int(p) for p in g.destination_port if int(p) in [23,3389,4444]})
        score, evidence = 0, []
        if failed>=5: score+=60; evidence.append(f"{failed} failed-login events")
        elif failed>=3: score+=35; evidence.append(f"{failed} failed-login events")
        elif failed==2: score+=15; evidence.append("Repeated failed-login activity")
        if max_bytes>=5_000_000: score+=35; evidence.append("Outbound transfer at least 5 MB")
        elif max_bytes>=1_000_000: score+=20; evidence.append("Elevated outbound data volume")
        if ports: score+=15; evidence.append("Review destination port(s): "+", ".join(map(str,ports)))
        score=min(score,100)
        output.append({
          "incident_id":incident_id,"source_ip":g.source_ip.iloc[0],
          "first_seen":g.timestamp.min(),"last_seen":g.timestamp.max(),
          "events":len(g),"failed_logins":failed,"risk_score":score,
          "risk_level":"High" if score>=60 else "Medium" if score>=30 else "Low",
          "evidence":"; ".join(evidence) if evidence else "No configured rule triggered"
        })
    return pd.DataFrame(output).sort_values(["risk_score","events"],ascending=False).reset_index(drop=True)

def chart(incidents):
    c=incidents.risk_level.value_counts().reindex(["High","Medium","Low"],fill_value=0).rename_axis("Risk level").reset_index(name="Incidents")
    fig=px.bar(c,x="Risk level",y="Incidents",color="Risk level",text="Incidents",
      color_discrete_map={"High":"#D46A6A","Medium":GOLD,"Low":"#6FA88B"})
    fig.update_layout(paper_bgcolor=NAVY,plot_bgcolor=NAVY,font_color=IVORY,showlegend=False,
      margin=dict(l=8,r=8,t=15,b=8),height=300,
      xaxis=dict(showgrid=False,title=""),
      yaxis=dict(showgrid=True,gridcolor="rgba(220,230,240,.12)",title="",rangemode="tozero"))
    fig.update_traces(textposition="outside")
    return fig

def timeline(events):
    c=events.set_index("timestamp").resample("5min").size().reset_index(name="Events")
    fig=px.line(c,x="timestamp",y="Events",markers=True)
    fig.update_traces(line_color=GOLD,marker_color=GOLD)
    fig.update_layout(paper_bgcolor=NAVY,plot_bgcolor=NAVY,font_color=IVORY,
      margin=dict(l=8,r=8,t=12,b=8),height=260,
      xaxis=dict(showgrid=False,title="Time"),
      yaxis=dict(showgrid=True,gridcolor="rgba(220,230,240,.12)",title="Events"))
    return fig

st.sidebar.markdown("## 🛡️ CyberShield")
st.sidebar.caption("INTELLIGENT INTEGRATED CYBER DEFENSE SYSTEM")
page=st.sidebar.radio("WORKSPACE",["Security Overview","Event Investigation","Event Correlation","Security Reports","About"])
st.sidebar.divider()
window=st.sidebar.selectbox("Correlation time window (minutes)",[5,10,15,30,60],index=1)
mode=st.sidebar.radio("Data source",["Sample dataset","Upload CSV"])
uploaded=st.sidebar.file_uploader("Upload event CSV",type=["csv"]) if mode=="Upload CSV" else None
st.sidebar.caption("Required: timestamp, source_ip, event_type. Optional: failed_logins, bytes_out, destination_port.")
if st.sidebar.button("Run security analysis",use_container_width=True):
    try:
        if mode=="Upload CSV":
            if uploaded is None: st.sidebar.warning("Upload a CSV first.")
            else:
                st.session_state.cs_events=analyse(pd.read_csv(uploaded),window)
                st.session_state.cs_source=uploaded.name
        else:
            st.session_state.cs_events=analyse(SAMPLE,window)
            st.session_state.cs_source="Built-in demonstration dataset"
        st.sidebar.success("Analysis completed.")
    except Exception as e: st.sidebar.error(str(e))

if "cs_events" not in st.session_state:
    st.session_state.cs_events=analyse(SAMPLE,window)
    st.session_state.cs_source="Built-in demonstration dataset"

events=st.session_state.cs_events
incidents=make_incidents(events)
rc=incidents.risk_level.value_counts()
high,medium,low=[int(rc.get(x,0)) for x in ["High","Medium","Low"]]
st.caption("DEFENSIVE SECURITY ANALYTICS PLATFORM")
st.title("CyberShield")
st.markdown('<div class="cs-sub">Intelligent Integrated Cyber Defense System · Security Event Monitoring & Risk Assessment</div>',unsafe_allow_html=True)

if page=="Security Overview":
    st.subheader("Security posture at a glance")
    a,b,c,d=st.columns(4)
    a.metric("Events analysed",len(events))
    b.metric("Correlated incidents",len(incidents))
    c.metric("High-risk incidents",high)
    d.metric("Unique source IPs",events.source_ip.nunique())
    left,right=st.columns([1.2,1])
    with left:
        st.markdown("#### Incident risk distribution")
        st.plotly_chart(chart(incidents),use_container_width=True,config={"displayModeBar":False})
    with right:
        st.markdown("#### Analyst attention")
        if high: st.error(f"{high} high-risk incident(s) need priority review.")
        elif medium: st.warning(f"{medium} medium-risk incident(s) should be reviewed.")
        else: st.success("No High- or Medium-risk incidents under current rules.")
        st.markdown(f"**Data source:** {st.session_state.cs_source}")
        st.markdown(f"**Correlation window:** {window} minutes")
    st.markdown("#### Event activity timeline")
    st.plotly_chart(timeline(events),use_container_width=True,config={"displayModeBar":False})
    st.markdown("#### Latest security events")
    st.dataframe(events.sort_values("timestamp",ascending=False).head(8)[
      ["timestamp","source_ip","event_type","failed_attempts_window","risk_level","risk_score"]],
      use_container_width=True,hide_index=True)
    st.info("Risk labels are rule-based triage indicators. They support human review and do not prove an attack.")

elif page=="Event Investigation":
    st.subheader("Event investigation")
    levels=st.multiselect("Risk level",["High","Medium","Low"],default=["High","Medium","Low"])
    ips=st.multiselect("Source IP",sorted(events.source_ip.unique()),default=sorted(events.source_ip.unique()))
    filtered=events[events.risk_level.isin(levels)&events.source_ip.isin(ips)]
    st.dataframe(filtered[["timestamp","source_ip","event_type","incident_id","failed_attempts_window","risk_level","risk_score","reason"]],
      use_container_width=True,hide_index=True)
    st.markdown("#### Investigate a source")
    if not filtered.empty:
        ip=st.selectbox("Choose source IP",sorted(filtered.source_ip.unique()))
        subset=filtered[filtered.source_ip==ip]
        for _,r in subset.iterrows():
            with st.expander(f"{r.timestamp} · {r.event_type} · {r.risk_level} ({r.risk_score}/100)"):
                st.write("**Incident:**",r.incident_id)
                st.write("**Evidence:**",r.reason)
                st.write("**Failed attempts in rolling window:**",int(r.failed_attempts_window))
    else: st.info("No events match the selected filters.")

elif page=="Event Correlation":
    st.subheader("Correlated security incidents")
    st.write("Events from the same source are grouped when consecutive records fall within the selected time window.")
    st.dataframe(incidents,use_container_width=True,hide_index=True)
    if not incidents.empty:
        selected=st.selectbox("Select an incident",incidents.incident_id.tolist())
        inc=incidents[incidents.incident_id==selected].iloc[0]
        related=events[events.incident_id==selected]
        x,y,z=st.columns(3)
        x.metric("Risk score",f"{inc.risk_score}/100")
        y.metric("Events",int(inc.events))
        z.metric("Failed logins",int(inc.failed_logins))
        st.write("**Source IP:**",inc.source_ip)
        st.write("**Evidence:**",inc.evidence)
        st.write("**Related events:**")
        st.dataframe(related[["timestamp","event_type","destination_port","bytes_out","risk_level","risk_score"]],
          use_container_width=True,hide_index=True)
    st.caption("Correlation is based on source IP and time proximity. It is a triage aid, not proof of a shared malicious cause.")

elif page=="Security Reports":
    st.subheader("Security assessment report")
    st.write("Generated:",datetime.now().strftime("%Y-%m-%d %H:%M"))
    st.write(f"Events: **{len(events)}** · Incidents: **{len(incidents)}** · Sources: **{events.source_ip.nunique()}**")
    st.write(f"High: **{high}** · Medium: **{medium}** · Low: **{low}**")
    priority=incidents[incidents.risk_level.isin(["High","Medium"])]
    if priority.empty: st.success("No High- or Medium-risk incidents flagged by current rules.")
    else: st.dataframe(priority,use_container_width=True,hide_index=True)
    st.download_button("Download event analysis CSV",events.to_csv(index=False).encode("utf-8"),"cybershield_event_analysis.csv","text/csv")
    st.download_button("Download incident report CSV",incidents.to_csv(index=False).encode("utf-8"),"cybershield_incident_report.csv","text/csv")

else:
    st.subheader("About this prototype")
    st.markdown("""
**CyberShield — Intelligent Integrated Cyber Defense System**

This educational defensive prototype demonstrates:
1. Security-event ingestion from a sample dataset or user-provided CSV.
2. Time-based grouping of consecutive events from the same source IP.
3. Rolling-window correlation of failed-login activity.
4. Transparent, rule-based risk scoring with evidence.
5. Incident investigation and downloadable event/incident reports.

**Current scope:** it analyses supplied sample or CSV records. It does not perform live network monitoring, scan systems, block traffic, or take automated response actions. Risk scores are illustrative triage aids, not proof of malicious activity.

**Next development:** richer log-source support, behavioural baselines, analyst feedback, and carefully evaluated machine-learning models.
""")

st.divider()
st.caption("CYBERSHIELD · DEFENSIVE SECURITY ANALYTICS · EDUCATIONAL PROTOTYPE")
