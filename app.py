#!/usr/bin/env python3
"""L5 — NetLens dashboard.

    streamlit run app.py                    # simulated traffic, no privileges
    sudo .venv/bin/streamlit run app.py     # live capture on a real interface

The UI holds no analysis logic: every number on this page comes off
`netlens.engine.Engine`.  Live panels are wrapped in scoped `st.fragment`s so
a refresh re-renders only that panel and never blocks or restarts the capture
thread (novelty N4).  Flow inspection deliberately sits outside the
auto-refresh so the ladder you are reading does not move under you.
"""

from __future__ import annotations

import time

import plotly.graph_objects as go
import streamlit as st

from netlens import config
from netlens.capture import list_interfaces, make_source
from netlens.engine import Engine
from netlens.explain import CONCEPTS, build_ladder, concept_for, interpret_flow
from netlens.flows import FEATURE_NAMES
from netlens.synth import ATTACK_CLASSES

st.set_page_config(page_title="NetLens — Network Packet Analyzer",
                   page_icon="🛰️", layout="wide",
                   initial_sidebar_state="expanded")

SEV_COLOR = {"critical": "#c0392b", "high": "#e67e22", "medium": "#d4ac0d",
             "low": "#2980b9", "info": "#7f8c8d"}
TIER_LABEL = {"rule": "T1 rule", "baseline": "T2 baseline", "model": "T3 model"}
DARK = st.get_option("theme.base") == "dark"
TEMPLATE = "plotly_dark" if DARK else "plotly_white"
GRID = "#3a3f4b" if DARK else "#e6e9ef"

st.markdown("""
<style>
  .block-container {padding-top: 2.2rem; max-width: 1500px;}
  .nl-alert {border-left: 4px solid #888; padding: .55rem .8rem; margin:.3rem 0;
             border-radius: 4px; background: rgba(128,128,128,.08);}
  .nl-alert b {font-size: .95rem;}
  .nl-meta {font-size: .78rem; opacity: .75; font-family: ui-monospace, monospace;}
  .nl-card {border: 1px solid rgba(128,128,128,.3); border-radius: 6px;
            padding: .8rem 1rem; margin: .4rem 0;}
  .nl-card h4 {margin: 0 0 .35rem 0; font-size: .95rem;}
  .nl-tag {display:inline-block; font-size:.7rem; padding:.1rem .45rem;
           border-radius:3px; background:rgba(128,128,128,.2); margin-right:.3rem;
           font-family: ui-monospace, monospace;}
  div[data-testid="stMetricValue"] {font-size: 1.5rem;}
</style>
""", unsafe_allow_html=True)


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def style_fig(fig, height=300, legend=True):
    fig.update_layout(
        template=TEMPLATE, height=height, margin=dict(l=10, r=10, t=30, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        showlegend=legend,
        legend=dict(orientation="h", y=-0.18, x=0, font=dict(size=10)),
        font=dict(size=11),
    )
    fig.update_xaxes(gridcolor=GRID, zeroline=False)
    fig.update_yaxes(gridcolor=GRID, zeroline=False)
    return fig


def concept_card(key: str, expanded: bool = False):
    """L4: bind a dashboard element to the networking principle behind it."""
    c = concept_for(key)
    with st.expander(f"Concept — {c['title']}", expanded=expanded):
        st.markdown(f"**{c['concept']}**")
        st.markdown(f"*What you are looking at:* {c['observed']}")
        st.markdown(c["why"])
        if c.get("where"):
            st.caption(c["where"])


# ============================================================== sidebar
def sidebar():
    st.sidebar.title("🛰️ NetLens")
    st.sidebar.caption("Network packet analyzer with visual dashboard")

    running = "engine" in st.session_state
    mode = st.sidebar.radio(
        "Traffic source",
        ["Simulated (no privileges)", "PCAP file", "Live interface"],
        disabled=running,
        help=("Simulated generates synthetic packets through the real pipeline — "
              "use it for demos. Live capture needs raw-socket access (sudo)."),
    )

    kwargs = {}
    if mode.startswith("Live"):
        ifaces = list_interfaces()
        if ifaces:
            default = next((i for i, n in enumerate(ifaces)
                            if n in ("en0", "eth0", "wlan0")), 0)
            kwargs["iface"] = st.sidebar.selectbox("Interface", ifaces,
                                                   index=default, disabled=running)
        else:
            kwargs["iface"] = st.sidebar.text_input("Interface", "en0",
                                                    disabled=running)
        kwargs["bpf"] = st.sidebar.text_input(
            "BPF filter (optional)", config.DEFAULT_BPF, disabled=running,
            placeholder="tcp or udp or icmp")
        st.sidebar.warning("Live capture needs root: "
                           "`sudo .venv/bin/streamlit run app.py`", icon="⚠️")
    elif mode.startswith("PCAP"):
        kwargs["path"] = st.sidebar.text_input(
            "PCAP path", str(config.CAPTURE_DIR / "capture.pcap"),
            disabled=running)
        kwargs["realtime"] = st.sidebar.checkbox("Replay at original timing",
                                                 True, disabled=running)
        kwargs["speed"] = st.sidebar.slider("Replay speed", 0.25, 10.0, 1.0, 0.25,
                                            disabled=running)
    else:
        kwargs["benign_rate"] = st.sidebar.slider(
            "Benign sessions / second", 0.5, 12.0, 3.0, 0.5, disabled=running)
        kwargs["auto_attacks"] = st.sidebar.checkbox(
            "Inject attacks automatically", True, disabled=running,
            help="Every 25-70 s, one attack scenario is launched.")

    st.sidebar.divider()
    st.sidebar.subheader("Detector tiers")
    enable_model = st.sidebar.checkbox(
        "T3 — supervised classifier", True, disabled=running,
        help="Random Forest trained on labelled attacks (train_model.py)")
    st.sidebar.caption("T1 rules and T2 Isolation Forest are always on.")

    st.sidebar.divider()
    refresh = st.sidebar.slider("Refresh interval (s)", 1.0, 10.0,
                                config.UI_REFRESH_SECONDS, 0.5)
    st.session_state["refresh"] = refresh

    c1, c2 = st.sidebar.columns(2)
    if not running:
        if c1.button("▶ Start", type="primary", use_container_width=True):
            src = make_source("live" if mode.startswith("Live")
                              else "pcap" if mode.startswith("PCAP") else "sim",
                              **kwargs)
            eng = Engine(src, enable_model=enable_model)
            eng.start()
            st.session_state["engine"] = eng
            st.session_state["mode"] = mode
            st.rerun()
    else:
        if c1.button("⏸ Stop", use_container_width=True):
            st.session_state["engine"].stop()
            st.session_state["stopped"] = True
            st.rerun()
        if c2.button("↺ Reset", use_container_width=True):
            st.session_state["engine"].stop()
            for k in ("engine", "stopped", "mode"):
                st.session_state.pop(k, None)
            st.rerun()

    if running and st.session_state.get("mode", "").startswith("Simulated"):
        st.sidebar.divider()
        st.sidebar.subheader("Inject attack")
        st.sidebar.caption("Replays a labelled attack scenario into the live "
                           "stream — nothing is sent on any network.")
        src = st.session_state["engine"].source
        for i in range(0, len(ATTACK_CLASSES), 2):
            cols = st.sidebar.columns(2)
            for col, name in zip(cols, ATTACK_CLASSES[i:i + 2]):
                if col.button(name.replace("_", " "), key=f"inj_{name}",
                              use_container_width=True):
                    src.inject(name)
                    st.toast(f"injected {name}", icon="💉")

    if running:
        st.sidebar.divider()
        s = st.session_state["engine"].status()
        st.sidebar.caption("**Detector status** "
                           "<span style='opacity:.6'>(snapshot — the live "
                           "figures are on the Detection model tab)</span>",
                           unsafe_allow_html=True)
        st.sidebar.caption(f"T1 · {s['rules']}")
        st.sidebar.caption(f"T2 · {s['baseline']}")
        st.sidebar.caption(f"T3 · {s['model']}")

    return mode, enable_model


# ============================================================== panels
def kpi_strip(eng):
    k = eng.kpis()
    cols = st.columns(7)
    cols[0].metric("Packets", f"{k['packets']:,}",
                   f"{k['pps_now']:.0f}/s now")
    cols[1].metric("Volume", fmt_bytes(k["bytes"]),
                   f"{fmt_bytes(k['bps_now'])}/s")
    cols[2].metric("Active flows", f"{k['active_flows']:,}",
                   f"{k['total_flows']:,} seen")
    cols[3].metric("Alerts", f"{k['alerts']:,}")
    cols[4].metric("Dropped", f"{k['dropped']:,}",
                   f"{k['drop_rate'] * 100:.2f}% of captured",
                   delta_color="inverse")
    cols[5].metric("Buffer", f"{k['buffered']:,}",
                   f"cap {config.RING_BUFFER_SIZE:,}")
    cols[6].metric("Pipeline latency", f"{k['tick_ms']:.1f} ms",
                   f"{k['elapsed']:.0f}s uptime")
    if k.get("error"):
        st.error(k["error"], icon="🚫")


def timeline_chart(eng):
    secs, pkts, byts = eng.timeline_series()
    rel = [s - secs[-1] for s in secs]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=rel, y=pkts, name="packets/s", fill="tozeroy",
                             line=dict(width=1.6, color="#2980b9"),
                             fillcolor="rgba(41,128,185,.18)"))
    fig.add_trace(go.Scatter(x=rel, y=[b / 1024 for b in byts], name="KB/s",
                             yaxis="y2", line=dict(width=1.6, color="#e67e22")))
    fig.update_layout(
        title="Traffic timeline",
        yaxis=dict(title="packets/s"),
        yaxis2=dict(title="KB/s", overlaying="y", side="right",
                    showgrid=False),
        xaxis=dict(title="seconds ago"),
    )
    return style_fig(fig, 290)


def protocol_chart(eng):
    items = eng.proto_counts.most_common(8)
    if not items:
        return None
    fig = go.Figure(go.Pie(
        labels=[k for k, _ in items], values=[v for _, v in items],
        hole=.55, textinfo="label+percent",
        marker=dict(colors=["#2980b9", "#27ae60", "#e67e22", "#8e44ad",
                            "#c0392b", "#16a085", "#d4ac0d", "#7f8c8d"]),
    ))
    fig.update_layout(title="Protocol mix")
    return style_fig(fig, 300, legend=False)


def bar_chart(items, title, color, horizontal=True):
    if not items:
        return None
    labels = [str(k) for k, _ in items][::-1]
    values = [v for _, v in items][::-1]
    fig = go.Figure(go.Bar(x=values, y=labels, orientation="h",
                           marker_color=color))
    fig.update_layout(title=title)
    return style_fig(fig, 300, legend=False)


def size_chart(eng):
    items = sorted(eng.size_hist.items())
    if not items:
        return None
    fig = go.Figure(go.Bar(x=[f"{k}-{k+99}" for k, _ in items],
                           y=[v for _, v in items], marker_color="#16a085"))
    fig.update_layout(title="Packet size distribution (bytes)",
                      xaxis=dict(tickangle=-45))
    return style_fig(fig, 300, legend=False)


def ladder_figure(steps, flow):
    """N3 — the captured flow redrawn as a sequence diagram."""
    n = len(steps)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=[0, 0], y=[0.4, -n - 0.4], mode="lines",
                             line=dict(color="#7f8c8d", width=2), hoverinfo="skip",
                             showlegend=False))
    fig.add_trace(go.Scatter(x=[1, 1], y=[0.4, -n - 0.4], mode="lines",
                             line=dict(color="#7f8c8d", width=2), hoverinfo="skip",
                             showlegend=False))

    phase_color = {"handshake": "#2980b9", "established": "#27ae60",
                   "data": "#16a085", "teardown": "#8e44ad",
                   "aborted": "#c0392b", "setup": "#7f8c8d"}

    for i, s in enumerate(steps):
        y = -(i + 1)
        fwd = s["direction"] == "->"
        col = phase_color.get(s["phase"], "#7f8c8d")
        fig.add_annotation(
            x=1 if fwd else 0, y=y, ax=0 if fwd else 1, ay=y,
            xref="x", yref="y", axref="x", ayref="y",
            showarrow=True, arrowhead=3, arrowsize=1.1, arrowwidth=1.7,
            arrowcolor=col,
        )
        fig.add_annotation(
            x=0.5, y=y + 0.3, xref="x", yref="y", showarrow=False,
            text=f"<b>{s['label']}</b>  <span style='font-size:10px'>"
                 f"{s['bytes']} B</span>",
            font=dict(size=11, color=col),
        )
        fig.add_annotation(x=-0.07, y=y, xref="x", yref="y", showarrow=False,
                           text=f"<span style='font-size:10px'>"
                                f"{s['t_ms']:.2f} ms</span>",
                           xanchor="right", font=dict(size=10))
        if s["note"]:
            fig.add_annotation(x=1.07, y=y, xref="x", yref="y", showarrow=False,
                               text=f"<span style='font-size:10px'>{s['note']}"
                                    f"</span>",
                               xanchor="left", align="left", font=dict(size=10))

    fig.add_annotation(x=0, y=0.75, text=f"<b>{flow.src_ip}</b><br>"
                       f"<span style='font-size:10px'>:{flow.src_port or '-'}</span>",
                       showarrow=False, font=dict(size=12))
    fig.add_annotation(x=1, y=0.75, text=f"<b>{flow.dst_ip}</b><br>"
                       f"<span style='font-size:10px'>:{flow.dst_port or '-'}</span>",
                       showarrow=False, font=dict(size=12))

    fig.update_xaxes(range=[-0.42, 2.25], visible=False)
    fig.update_yaxes(range=[-n - 1, 1.4], visible=False)
    fig.update_layout(template=TEMPLATE, height=max(280, 46 * n + 90),
                      margin=dict(l=10, r=10, t=10, b=10), showlegend=False,
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


def alert_block(a):
    col = SEV_COLOR.get(a.severity, "#888")
    conf = f" · confidence {a.confidence:.0%}" if a.confidence else ""
    st.markdown(
        f"<div class='nl-alert' style='border-left-color:{col}'>"
        f"<b style='color:{col}'>{a.severity.upper()}</b> &nbsp; <b>{a.title}</b>"
        f"<br><span class='nl-meta'>"
        f"{time.strftime('%H:%M:%S', time.localtime(a.ts))} · "
        f"{TIER_LABEL.get(a.tier, a.tier)}{conf} · "
        f"{a.source}{' → ' + a.target if a.target else ''}</span>"
        f"<br>{a.detail}</div>", unsafe_allow_html=True)


# ============================================================== main
mode, enable_model = sidebar()

st.title("Network Packet Analyzer with Visual Dashboard")
st.caption("NetLens · live capture → flow analytics → hybrid detection → "
           "explained in protocol terms")

if "engine" not in st.session_state:
    st.info("Pick a traffic source in the sidebar and press **Start**. "
            "*Simulated* needs no privileges and is the right choice for a demo; "
            "*Live interface* captures real packets and needs `sudo`.", icon="▶️")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""<div class='nl-card'><h4>Pipeline</h4>
        <span class='nl-tag'>L1</span> capture · AsyncSniffer + ring buffer<br>
        <span class='nl-tag'>L2</span> parse + bidirectional flow table<br>
        <span class='nl-tag'>L3</span> rules + Isolation Forest + classifier<br>
        <span class='nl-tag'>L4</span> concept cards + session ladder<br>
        <span class='nl-tag'>L5</span> this dashboard
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class='nl-card'><h4>Detection tiers</h4>
        <b>T1 rules</b> — port scan, SYN flood, DNS entropy, ARP conflict,
        ICMP flood, brute force. No training.<br>
        <b>T2 Isolation Forest</b> — self-baselined on this network's own first
        {config.BASELINE_SECONDS:.0f}s. Label-free.<br>
        <b>T3 classifier</b> — Random Forest trained on labelled attacks; names
        the class with a confidence.
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""<div class='nl-card'><h4>Features per flow</h4>
        {len(FEATURE_NAMES)} statistics computed from both directions:
        duration, byte and packet counts, size distribution, inter-arrival
        timing, direction ratios, TCP flag composition, TTL and DNS entropy.
        The same code path builds them for live traffic and for training.
        </div>""", unsafe_allow_html=True)
    st.stop()

eng: Engine = st.session_state["engine"]
refresh = st.session_state.get("refresh", config.UI_REFRESH_SECONDS)
stopped = st.session_state.get("stopped", False)
if stopped:
    st.warning("Capture stopped — the data below is the final state.", icon="⏸")


@st.fragment(run_every=None if stopped else min(refresh, 2.0))
def pipeline_pump():
    """Advance L1-L4 on a timer.

    Deliberately rendered *outside* the tab set: Streamlit pauses the
    auto-refresh of a fragment that sits inside a tab the user is not looking
    at, which would stall the pipeline the moment you opened the Alerts tab.
    The ring buffer would absorb the pause without losing packets — that is
    what it is for — but the dashboard should not lean on that.
    """
    if not stopped:
        eng.tick()
    k = eng.kpis()
    st.caption(
        f"⏱ {time.strftime('%H:%M:%S')} &nbsp;·&nbsp; "
        f"{k['packets']:,} packets &nbsp;·&nbsp; {k['pps_now']:.0f} pkt/s "
        f"&nbsp;·&nbsp; {k['active_flows']} active flows &nbsp;·&nbsp; "
        f"{k['alerts']} alerts &nbsp;·&nbsp; {k['dropped']} dropped "
        f"&nbsp;·&nbsp; {k['tick_ms']:.1f} ms/tick",
        unsafe_allow_html=True)


pipeline_pump()

tabs = st.tabs(["Live dashboard", "Alerts", "Flows & session ladder",
                "Detection model", "Concept library"])

# ---------------------------------------------------------------- tab 1
with tabs[0]:
    @st.fragment(run_every=None if stopped else refresh)
    def live_dashboard():
        # No tick here — pipeline_pump() above owns advancing the pipeline so
        # it keeps running whichever tab is open. This panel only renders.
        kpi_strip(eng)
        st.plotly_chart(timeline_chart(eng), use_container_width=True,
                        key="tl")
        c1, c2 = st.columns([1, 1.4])
        f = protocol_chart(eng)
        if f:
            c1.plotly_chart(f, use_container_width=True, key="proto")
        f = bar_chart(eng.top_ports(config.TOP_N), "Top destination ports",
                      "#8e44ad")
        if f:
            c2.plotly_chart(f, use_container_width=True, key="ports")
        c3, c4 = st.columns([1.4, 1])
        f = bar_chart([(ip, b) for ip, b in eng.top_talkers(config.TOP_N)],
                      "Top talkers (bytes sent)", "#2980b9")
        if f:
            c3.plotly_chart(f, use_container_width=True, key="talkers")
        f = size_chart(eng)
        if f:
            c4.plotly_chart(f, use_container_width=True, key="sizes")

        st.caption(f"panel re-rendered {time.strftime('%H:%M:%S')} · "
                   f"scoped fragment, {refresh:.1f}s · "
                   f"capture thread never blocked")

    live_dashboard()

    cc = st.columns(4)
    with cc[0]:
        concept_card("protocol_mix")
    with cc[1]:
        concept_card("throughput")
    with cc[2]:
        concept_card("top_talkers")
    with cc[3]:
        concept_card("mtu_fragmentation")

# ---------------------------------------------------------------- tab 2
with tabs[1]:
    st.subheader("Alert feed")
    fc1, fc2, fc3 = st.columns([1, 1, 2])
    sev_filter = fc1.multiselect("Severity",
                                 ["critical", "high", "medium", "low"],
                                 default=["critical", "high", "medium"],
                                 key="sev_f")
    tier_filter = fc2.multiselect("Tier", ["rule", "baseline", "model"],
                                  default=["rule", "baseline", "model"],
                                  key="tier_f")
    limit = fc3.slider("Show most recent", 5, 100, 25, key="alim")

    @st.fragment(run_every=None if stopped else refresh)
    def alert_feed():
        alerts = [a for a in eng.detector.alerts
                  if a.severity in sev_filter and a.tier in tier_filter][:limit]
        counts = eng.detector.counts
        if counts:
            st.caption("by kind: " + " · ".join(
                f"**{k}** {v}" for k, v in
                sorted(counts.items(), key=lambda x: -x[1])))
        if not alerts:
            st.success("No alerts matching the filter.", icon="✅")
            return
        for a in alerts:
            alert_block(a)
            with st.expander("Evidence and concept", expanded=False):
                e1, e2 = st.columns([1, 1.3])
                with e1:
                    st.caption("**Evidence**")
                    st.json(a.evidence, expanded=True)
                    if a.flow_id:
                        st.caption(f"flow `{a.flow_id}`")
                with e2:
                    c = concept_for(a.kind)
                    st.caption(f"**{c['title']}** — {c['concept']}")
                    st.markdown(f"*Observed:* {c['observed']}")
                    st.markdown(c["why"])
                    if c.get("where"):
                        st.caption(c["where"])

    alert_feed()

# ---------------------------------------------------------------- tab 3
with tabs[2]:
    st.subheader("Flow table")
    st.caption("Deliberately not auto-refreshing: a ladder you are reading "
               "should not move. Use the button to pull the current state.")
    b1, b2, b3 = st.columns([1, 1, 3])
    if b1.button("↻ Reload flows", use_container_width=True):
        st.session_state["flow_nonce"] = time.time()
    only_flagged = b2.checkbox("Flagged only", False)

    rows = eng.flow_rows(limit=250, only_flagged=only_flagged)
    if not rows:
        st.info("No flows yet — give the capture a few seconds.")
    else:
        st.dataframe(rows, use_container_width=True, height=300,
                     hide_index=True)
        st.caption(f"{len(rows)} flows shown · "
                   f"{eng.flows.stats()['active_flows']} active, "
                   f"{eng.flows.stats()['completed_flows']} completed "
                   f"(idle {config.FLOW_IDLE_TIMEOUT:.0f}s / "
                   f"active {config.FLOW_ACTIVE_TIMEOUT:.0f}s timeouts)")

        st.divider()
        st.subheader("TCP session ladder")
        st.caption("The handshake, data phase and teardown rebuilt from the "
                   "actual captured packets — not an illustration.")

        choices = {
            f"{r['source']} → {r['destination']}  [{r['proto']} "
            f"{r['packets']}p {fmt_bytes(r['bytes'])}]"
            f"{'  ⚠ ' + r['verdict'] if r['verdict'] else ''}": r["flow_id"]
            for r in rows
        }
        pick = st.selectbox("Flow", list(choices.keys()), key="flowpick")
        flow = eng.flows.get(choices[pick]) if pick else None

        if flow is None:
            st.info("That flow has been evicted from the table. Reload the list.")
        else:
            steps = build_ladder(flow)
            lc, rc = st.columns([1.5, 1])
            with lc:
                if steps:
                    st.plotly_chart(ladder_figure(steps, flow),
                                    use_container_width=True, key="ladder")
                    if len(flow.ladder) >= config.MAX_LADDER_PACKETS:
                        st.caption(f"showing the first "
                                   f"{config.MAX_LADDER_PACKETS} packets "
                                   f"(config.MAX_LADDER_PACKETS)")
                else:
                    st.info("No packets retained for this flow.")
            with rc:
                st.markdown("**What this flow did**")
                reading = interpret_flow(flow)
                for line in reading.get("lines", []):
                    st.markdown(f"- {line}")
                st.markdown("**Concepts evidenced here**")
                for key in reading.get("concepts", [])[:4]:
                    concept_card(key)

            with st.expander(f"All {len(FEATURE_NAMES)} flow features "
                             f"(the model's input vector)"):
                feats = flow.features()
                fcols = st.columns(3)
                for i, name in enumerate(FEATURE_NAMES):
                    v = feats[name]
                    fcols[i % 3].markdown(
                        f"<span class='nl-tag'>{name}</span> "
                        f"{v:,.3f}" if isinstance(v, float)
                        else f"<span class='nl-tag'>{name}</span> {v}",
                        unsafe_allow_html=True)

            if steps:
                with st.expander("Packet-by-packet table"):
                    st.dataframe(steps, use_container_width=True,
                                 hide_index=True)

        concept_card("flow")
        concept_card("flow_timeout")

# ---------------------------------------------------------------- tab 4
with tabs[3]:
    st.subheader("Detection model")

    @st.fragment(run_every=None if stopped else refresh)
    def tier_status():
        s = eng.status()
        t1, t2, t3 = st.columns(3)
        t1.markdown(f"""<div class='nl-card'><h4>T1 — Deterministic rules</h4>
        <span class='nl-tag'>no training</span><br>{s['rules']}<br><br>
        Port scan ≥ {config.PORTSCAN_MIN_PORTS} ports · sweep ≥
        {config.PORTSCAN_MIN_HOSTS} hosts · SYN flood ≥
        {config.SYNFLOOD_MIN_SYNS} SYNs at {config.SYNFLOOD_RATIO:.0f}:1 ·
        DNS entropy ≥ {config.DNS_ENTROPY_THRESHOLD} bits/char · ICMP ≥
        {config.ICMPFLOOD_MIN_PKTS}/window · brute force ≥
        {config.BRUTE_MIN_ATTEMPTS} attempts · ARP MAC conflict
        </div>""", unsafe_allow_html=True)
        t2.markdown(f"""<div class='nl-card'><h4>T2 — Isolation Forest</h4>
        <span class='nl-tag'>label-free</span><br>{s['baseline']}<br><br>
        Fitted on this network's own first {config.BASELINE_SECONDS:.0f}s, so
        'normal' is defined locally. Alerts below a decision score of
        {config.IFOREST_ALERT_SCORE:+.2f}. Finds novel shapes, but cannot name
        them.
        </div>""", unsafe_allow_html=True)
        t3.markdown(f"""<div class='nl-card'><h4>T3 — Attack classifier</h4>
        <span class='nl-tag'>supervised</span><br>{s['model']}<br><br>
        Needs ≥ {config.SUPERVISED_MIN_CONFIDENCE:.0%} confidence before it
        speaks. Trained offline on labelled attack flows; names the class and
        shows which features drove the call.
        </div>""", unsafe_allow_html=True)

        st.caption("by tier: " + (" · ".join(f"**{TIER_LABEL.get(k, k)}** {v}"
               for k, v in s["by_tier"].items()) or "no alerts yet"))

    tier_status()

    st.divider()
    concept_card("model_tier", expanded=True)

    clf = eng.detector.classifier
    if clf is None or not clf.available:
        st.warning((clf.error if clf else "classifier disabled")
                   + "\n\nTrain it with:\n```bash\npython train_model.py\n```",
                   icon="⚠️")
    else:
        b = clf.bundle
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Test accuracy", f"{b['test_accuracy']:.1%}")
        m2.metric("Macro F1", f"{b['test_macro_f1']:.3f}")
        m3.metric("CV macro F1", f"{b['cv_macro_f1']:.3f}")
        m4.metric("Training flows", f"{b['n_train'] + b['n_test']:,}")

        st.markdown("**Classes this model can name**")
        st.markdown(" ".join(f"<span class='nl-tag'>{c}</span>"
                             for c in b["classes"]), unsafe_allow_html=True)

        st.markdown("**Per-class performance on held-out flows**")
        st.code(b["report"], language="text")

        i1, i2 = st.columns(2)
        cm_png = config.DATA_DIR / "confusion_matrix.png"
        fi_png = config.DATA_DIR / "feature_importance.png"
        if cm_png.exists():
            i1.image(str(cm_png), use_container_width=True)
        if fi_png.exists():
            i2.image(str(fi_png), use_container_width=True)
        if not cm_png.exists():
            st.caption("Run `python evaluate.py` to generate the confusion "
                       "matrix and feature-importance plots.")

        st.markdown("**Isolation Forest, measured on the same labelled set**")
        st.markdown(
            f"- flags **{b.get('iforest_attack_recall', 0):.1%}** of attack "
            f"flows as anomalous\n"
            f"- **{b.get('iforest_benign_fp', 0):.1%}** false positives on "
            f"benign flows\n"
            f"- it generalises to attacks it was never shown, but reports only "
            f"*unusual* — which is precisely why T3 exists alongside it.")
        st.caption(f"model file: `{config.MODEL_PATH}` · trained "
                   f"{b['trained_at']} · seed {b['seed']} · "
                   f"{b['flows_per_class']} flows/class"
                   + (f" · extra PCAPs: {b['extra_pcaps']}"
                      if b.get("extra_pcaps") else ""))

# ---------------------------------------------------------------- tab 5
with tabs[4]:
    st.subheader("Concept library")
    st.caption("Every metric and alert in this dashboard is bound to one of "
               "these cards (novelty N2). This is the whole registry.")
    groups = {
        "Dashboard metrics": ["protocol_mix", "throughput", "top_talkers",
                              "ports", "flow", "flow_timeout"],
        "Protocol behaviour": ["three_way_handshake", "tcp_teardown",
                               "retransmission", "dns_resolution",
                               "tls_handshake", "ttl", "mtu_fragmentation",
                               "arp", "icmp"],
        "Attacks and detection": ["port_scan", "host_sweep", "syn_flood",
                                  "dns_tunnel", "icmp_flood", "brute_force",
                                  "ssh_brute_force", "slowloris", "data_exfil",
                                  "arp_spoof", "anomalous_flow", "model_tier"],
    }
    for group, keys in groups.items():
        st.markdown(f"#### {group}")
        cols = st.columns(2)
        for i, key in enumerate(keys):
            c = CONCEPTS[key]
            with cols[i % 2]:
                st.markdown(
                    f"<div class='nl-card'><h4>{c['title']}</h4>"
                    f"<span class='nl-tag'>{c['concept']}</span><br><br>"
                    f"<i>{c['observed']}</i><br><br>{c['why']}"
                    + (f"<br><br><span class='nl-meta'>{c['where']}</span>"
                       if c.get("where") else "")
                    + "</div>", unsafe_allow_html=True)
