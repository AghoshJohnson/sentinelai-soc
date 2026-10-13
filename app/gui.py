"""
gui.py - Streamlit GUI for AI SOC Assistant

A professional, analyst-grade web interface for log analysis.
Provides file upload, live analysis, and rich visualisations.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path

# Bootstrap path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
import streamlit.components.v1 as components

# ---------------------------------------------------------------------------
# Page configuration — must be first Streamlit call
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AI SOC Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/lonewolf273/ai-soc-assistant",
        "Report a bug": "https://github.com/lonewolf273/ai-soc-assistant/issues",
        "About": "# AI SOC Assistant\nOffline-first AI-powered threat detection.",
    },
)

from dotenv import load_dotenv
load_dotenv()

from app.core.analyzer import analyse_log_file, save_report, AnalysisResult
from app.core.ollama_client import OllamaClient, DEFAULT_MODEL

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.WARNING)


# ---------------------------------------------------------------------------
# CSS styling — GAMING / CYBERPUNK HUD THEME
# ---------------------------------------------------------------------------

CUSTOM_CSS = """
<style>
    /* ============ FONTS ============ */
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

    :root {
        --primary: #00d4ff;
        --primary-dim: #0090b0;
        --danger: #ff2a4b;
        --warning: #ffa500;
        --success: #00ff9d;
        --accent: #b026ff;
        --surface: #0a0e1a;
        --card: #0d1526;
        --card-2: #111a2e;
        --grid: rgba(0, 212, 255, 0.06);
    }

    /* ============ GLOBAL APP BACKGROUND ============ */
    .stApp {
        background:
            radial-gradient(ellipse at top left, rgba(176, 38, 255, 0.12) 0%, transparent 50%),
            radial-gradient(ellipse at bottom right, rgba(0, 212, 255, 0.12) 0%, transparent 50%),
            linear-gradient(rgba(0, 212, 255, 0.035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 212, 255, 0.035) 1px, transparent 1px),
            linear-gradient(180deg, #05070f 0%, #0a0e1a 50%, #06090f 100%);
        background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px, 100% 100%;
        background-attachment: fixed;
        color: #d8e3f0;
        font-family: 'Rajdhani', -apple-system, sans-serif;
    }

    /* Scanline overlay */
    .stApp::before {
        content: "";
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        background: repeating-linear-gradient(
            0deg,
            rgba(0, 0, 0, 0.08) 0px,
            rgba(0, 0, 0, 0.08) 1px,
            transparent 1px,
            transparent 3px
        );
        pointer-events: none;
        z-index: 1;
        opacity: 0.4;
    }

    /* Animated top border strip */
    .stApp::after {
        content: "";
        position: fixed;
        top: 0; left: 0; right: 0;
        height: 3px;
        background: linear-gradient(90deg,
            transparent, #00d4ff, #b026ff, #ff2a4b, #00d4ff, transparent);
        background-size: 300% 100%;
        animation: borderScan 6s linear infinite;
        z-index: 9999;
        box-shadow: 0 0 12px rgba(0, 212, 255, 0.7);
    }

    @keyframes borderScan {
        0% { background-position: 0% 0; }
        100% { background-position: 300% 0; }
    }

    @keyframes pulseGlow {
        0%, 100% { box-shadow: 0 0 8px rgba(0, 212, 255, 0.35), inset 0 0 8px rgba(0, 212, 255, 0.05); }
        50%      { box-shadow: 0 0 24px rgba(0, 212, 255, 0.75), inset 0 0 16px rgba(0, 212, 255, 0.12); }
    }

    @keyframes flicker {
        0%, 100% { opacity: 1; }
        45% { opacity: 0.85; }
        46% { opacity: 0.4; }
        47% { opacity: 1; }
    }

    @keyframes sweep {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(200%); }
    }

    /* ============ TYPOGRAPHY ============ */
    h1, h2, h3, h4 {
        font-family: 'Orbitron', sans-serif !important;
        letter-spacing: 0.06em;
        color: #e6f4ff !important;
    }

    p, span, div, label, li {
        font-family: 'Rajdhani', sans-serif;
    }

    code, pre, .stCode, .stJson {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* ============ METRIC CARDS ============ */
    div[data-testid="metric-container"] {
        background:
            linear-gradient(135deg, rgba(13, 21, 38, 0.95) 0%, rgba(17, 26, 46, 0.95) 100%);
        border: 1px solid rgba(0, 212, 255, 0.35);
        border-radius: 4px 12px 4px 12px;
        padding: 1rem 1.1rem;
        position: relative;
        overflow: hidden;
        box-shadow:
            0 0 0 1px rgba(0, 212, 255, 0.05),
            0 4px 24px rgba(0, 0, 0, 0.6),
            inset 0 0 20px rgba(0, 212, 255, 0.04);
        transition: all 0.25s ease;
    }

    div[data-testid="metric-container"]::before {
        content: "";
        position: absolute;
        top: 0; left: 0;
        width: 40px; height: 3px;
        background: linear-gradient(90deg, #00d4ff, #b026ff);
        box-shadow: 0 0 10px #00d4ff;
    }

    div[data-testid="metric-container"]::after {
        content: "";
        position: absolute;
        bottom: 0; right: 0;
        width: 40px; height: 3px;
        background: linear-gradient(90deg, #b026ff, #00d4ff);
        box-shadow: 0 0 10px #b026ff;
    }

    div[data-testid="metric-container"]:hover {
        border-color: rgba(0, 212, 255, 0.9);
        box-shadow:
            0 0 24px rgba(0, 212, 255, 0.4),
            inset 0 0 24px rgba(0, 212, 255, 0.08);
        transform: translateY(-2px);
    }

    div[data-testid="metric-container"] label {
        color: #6fdcff !important;
        font-size: 0.7rem;
        font-family: 'Orbitron', sans-serif !important;
        text-transform: uppercase;
        letter-spacing: 0.15em;
        font-weight: 700;
    }

    div[data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 900;
        text-shadow: 0 0 12px rgba(0, 212, 255, 0.6);
    }

    /* ============ ALERT BOXES ============ */
    .alert-critical, .alert-high, .alert-medium, .alert-low {
        position: relative;
        border-radius: 4px 12px 4px 12px;
        padding: 1rem 1.25rem;
        margin: 0.65rem 0;
        overflow: hidden;
        transition: transform 0.2s ease;
    }

    .alert-critical:hover, .alert-high:hover,
    .alert-medium:hover, .alert-low:hover {
        transform: translateX(4px);
    }

    .alert-critical {
        background: linear-gradient(135deg, rgba(255, 42, 75, 0.18), rgba(255, 42, 75, 0.04));
        border: 1px solid rgba(255, 42, 75, 0.5);
        border-left: 4px solid #ff2a4b;
        box-shadow: 0 0 18px rgba(255, 42, 75, 0.25), inset 0 0 30px rgba(255, 42, 75, 0.05);
    }
    .alert-high {
        background: linear-gradient(135deg, rgba(255, 100, 50, 0.18), rgba(255, 100, 50, 0.04));
        border: 1px solid rgba(255, 100, 50, 0.5);
        border-left: 4px solid #ff6432;
        box-shadow: 0 0 18px rgba(255, 100, 50, 0.22), inset 0 0 30px rgba(255, 100, 50, 0.05);
    }
    .alert-medium {
        background: linear-gradient(135deg, rgba(255, 165, 0, 0.18), rgba(255, 165, 0, 0.04));
        border: 1px solid rgba(255, 165, 0, 0.5);
        border-left: 4px solid #ffa500;
        box-shadow: 0 0 18px rgba(255, 165, 0, 0.2), inset 0 0 30px rgba(255, 165, 0, 0.05);
    }
    .alert-low {
        background: linear-gradient(135deg, rgba(0, 255, 157, 0.14), rgba(0, 255, 157, 0.03));
        border: 1px solid rgba(0, 255, 157, 0.4);
        border-left: 4px solid #00ff9d;
        box-shadow: 0 0 18px rgba(0, 255, 157, 0.18), inset 0 0 30px rgba(0, 255, 157, 0.04);
    }

    /* ============ MITRE BADGE ============ */
    .mitre-badge {
        display: inline-block;
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.2), rgba(176, 38, 255, 0.15));
        border: 1px solid rgba(0, 212, 255, 0.5);
        border-radius: 3px 10px 3px 10px;
        padding: 0.25rem 0.85rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        color: #6fdcff;
        margin: 0.2rem;
        text-shadow: 0 0 8px rgba(0, 212, 255, 0.5);
        box-shadow: 0 0 10px rgba(0, 212, 255, 0.15);
    }

    /* ============ SECTION HEADERS ============ */
    .section-header {
        font-family: 'Orbitron', sans-serif;
        font-size: 1.05rem;
        font-weight: 700;
        color: #6fdcff;
        border-bottom: 1px solid rgba(0, 212, 255, 0.25);
        padding: 0.4rem 0 0.6rem 0.9rem;
        margin-bottom: 1rem;
        margin-top: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 0.15em;
        position: relative;
        text-shadow: 0 0 12px rgba(0, 212, 255, 0.4);
    }

    .section-header::before {
        content: "";
        position: absolute;
        left: 0; top: 50%;
        transform: translateY(-50%);
        width: 4px;
        height: 60%;
        background: linear-gradient(180deg, #00d4ff, #b026ff);
        box-shadow: 0 0 12px #00d4ff;
        border-radius: 2px;
    }

    .section-header::after {
        content: "";
        position: absolute;
        bottom: -1px; left: 0;
        width: 120px;
        height: 2px;
        background: linear-gradient(90deg, #00d4ff, transparent);
        box-shadow: 0 0 10px #00d4ff;
    }

    /* ============ SEVERITY TEXT ============ */
    .sev-critical { color: #ff2a4b; font-weight: 900; font-size: 1.5rem; text-shadow: 0 0 14px #ff2a4b; }
    .sev-high     { color: #ff6432; font-weight: 900; font-size: 1.5rem; text-shadow: 0 0 14px #ff6432; }
    .sev-medium   { color: #ffa500; font-weight: 900; font-size: 1.5rem; text-shadow: 0 0 14px #ffa500; }
    .sev-low      { color: #00ff9d; font-weight: 900; font-size: 1.5rem; text-shadow: 0 0 14px #00ff9d; }

    /* ============ SIDEBAR ============ */
    section[data-testid="stSidebar"] {
        background:
            linear-gradient(180deg, rgba(5, 7, 15, 0.98) 0%, rgba(10, 14, 26, 0.98) 100%);
        border-right: 1px solid rgba(0, 212, 255, 0.25);
        box-shadow: 4px 0 30px rgba(0, 212, 255, 0.08);
    }

    section[data-testid="stSidebar"] > div {
        padding-top: 1rem;
    }

    section[data-testid="stSidebar"] h3 {
        color: #6fdcff !important;
        text-shadow: 0 0 12px rgba(0, 212, 255, 0.5);
        font-family: 'Orbitron', sans-serif !important;
        letter-spacing: 0.1em;
    }

    section[data-testid="stSidebar"] .stMarkdown strong {
        color: #00d4ff;
        font-family: 'Orbitron', sans-serif;
        font-size: 0.8rem;
        letter-spacing: 0.1em;
    }

    /* ============ BUTTONS ============ */
    .stButton > button {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.15), rgba(176, 38, 255, 0.15));
        border: 1px solid rgba(0, 212, 255, 0.7);
        color: #6fdcff;
        font-family: 'Orbitron', sans-serif;
        font-weight: 700;
        letter-spacing: 0.15em;
        text-transform: uppercase;
        border-radius: 3px 10px 3px 10px;
        padding: 0.6rem 1.4rem;
        transition: all 0.2s ease;
        box-shadow: 0 0 12px rgba(0, 212, 255, 0.2);
        position: relative;
        overflow: hidden;
    }

    .stButton > button:hover {
        background: linear-gradient(135deg, rgba(0, 212, 255, 0.35), rgba(176, 38, 255, 0.35));
        border-color: #00d4ff;
        color: #ffffff;
        box-shadow: 0 0 28px rgba(0, 212, 255, 0.75), inset 0 0 20px rgba(0, 212, 255, 0.15);
        transform: translateY(-1px);
        text-shadow: 0 0 8px rgba(0, 212, 255, 0.8);
    }

    .stButton > button:active {
        transform: translateY(0);
    }

    /* ============ DOWNLOAD BUTTON ============ */
    .stDownloadButton > button {
        background: linear-gradient(135deg, rgba(0, 255, 157, 0.12), rgba(0, 212, 255, 0.12));
        border: 1px solid rgba(0, 255, 157, 0.6);
        color: #00ff9d;
        font-family: 'Orbitron', sans-serif;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        border-radius: 3px 10px 3px 10px;
        box-shadow: 0 0 12px rgba(0, 255, 157, 0.2);
    }

    .stDownloadButton > button:hover {
        background: linear-gradient(135deg, rgba(0, 255, 157, 0.3), rgba(0, 212, 255, 0.3));
        color: #ffffff;
        box-shadow: 0 0 24px rgba(0, 255, 157, 0.6);
    }

    /* ============ FILE UPLOADER ============ */
    section[data-testid="stFileUploaderDropzone"] {
        background: linear-gradient(135deg, rgba(13, 21, 38, 0.6), rgba(17, 26, 46, 0.6)) !important;
        border: 2px dashed rgba(0, 212, 255, 0.4) !important;
        border-radius: 8px 20px 8px 20px !important;
        transition: all 0.25s ease;
        box-shadow: inset 0 0 30px rgba(0, 212, 255, 0.05);
    }

    section[data-testid="stFileUploaderDropzone"]:hover {
        border-color: #00d4ff !important;
        box-shadow: 0 0 24px rgba(0, 212, 255, 0.35), inset 0 0 40px rgba(0, 212, 255, 0.1);
    }

    /* ============ TABS ============ */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        border-bottom: 1px solid rgba(0, 212, 255, 0.2);
        padding-bottom: 4px;
        background: transparent;
    }

    .stTabs [data-baseweb="tab"] {
        background: rgba(13, 21, 38, 0.7);
        border: 1px solid rgba(0, 212, 255, 0.2);
        border-radius: 3px 10px 0 0;
        color: #8892a4;
        font-family: 'Orbitron', sans-serif;
        font-weight: 600;
        font-size: 0.78rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        padding: 0.6rem 1rem;
        transition: all 0.2s ease;
    }

    .stTabs [data-baseweb="tab"]:hover {
        color: #6fdcff;
        border-color: rgba(0, 212, 255, 0.5);
        background: rgba(0, 212, 255, 0.08);
    }

    .stTabs [aria-selected="true"] {
        background: linear-gradient(180deg, rgba(0, 212, 255, 0.25), rgba(0, 212, 255, 0.05)) !important;
        color: #ffffff !important;
        border-color: #00d4ff !important;
        border-bottom-color: transparent !important;
        box-shadow: 0 -2px 12px rgba(0, 212, 255, 0.4);
    }

    .stTabs [data-baseweb="tab-highlight"] {
        background: #00d4ff;
        box-shadow: 0 0 10px #00d4ff;
    }

    /* ============ EXPANDER ============ */
    .streamlit-expanderHeader, details > summary {
        background: rgba(13, 21, 38, 0.7) !important;
        border: 1px solid rgba(0, 212, 255, 0.2) !important;
        border-radius: 6px !important;
        color: #6fdcff !important;
        font-family: 'Orbitron', sans-serif !important;
        letter-spacing: 0.08em;
    }

    details > summary:hover {
        border-color: #00d4ff !important;
        box-shadow: 0 0 14px rgba(0, 212, 255, 0.3);
    }

    /* ============ DATAFRAME ============ */
    .stDataFrame {
        border: 1px solid rgba(0, 212, 255, 0.3);
        border-radius: 6px;
        box-shadow: 0 0 18px rgba(0, 212, 255, 0.1);
        overflow: hidden;
    }

    /* ============ SPINNER ============ */
    .stSpinner > div {
        border-top-color: #00d4ff !important;
        filter: drop-shadow(0 0 8px #00d4ff);
    }

    /* ============ ALERTS / TOASTS ============ */
    div[data-testid="stAlert"] {
        border-radius: 4px 12px 4px 12px;
        border-left-width: 4px;
        font-family: 'Rajdhani', sans-serif;
    }

    /* ============ SCROLLBAR ============ */
    ::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    ::-webkit-scrollbar-track {
        background: rgba(0, 212, 255, 0.03);
    }
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #00d4ff, #b026ff);
        border-radius: 5px;
        box-shadow: 0 0 8px rgba(0, 212, 255, 0.5);
    }
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, #6fdcff, #d060ff);
    }

    /* ============ SELECT / INPUT ============ */
    .stSelectbox > div > div, .stTextInput > div > div > input {
        background: rgba(13, 21, 38, 0.8) !important;
        border: 1px solid rgba(0, 212, 255, 0.25) !important;
        color: #d8e3f0 !important;
        font-family: 'Rajdhani', sans-serif !important;
        border-radius: 4px !important;
    }

    .stSelectbox > div > div:hover, .stTextInput > div > div > input:focus {
        border-color: #00d4ff !important;
        box-shadow: 0 0 12px rgba(0, 212, 255, 0.3);
    }

    /* ============ TOGGLE ============ */
    [data-testid="stToggle"] label span {
        color: #c0c8d4 !important;
        font-family: 'Rajdhani', sans-serif;
    }

    /* ============ HERO / HEADER GLOW ============ */
    .hero-title {
        font-family: 'Orbitron', sans-serif;
        font-size: 3rem;
        font-weight: 900;
        letter-spacing: 0.08em;
        background: linear-gradient(90deg, #00d4ff, #b026ff, #00d4ff);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        animation: gradientShift 4s ease infinite;
        text-align: center;
        filter: drop-shadow(0 0 20px rgba(0, 212, 255, 0.6));
    }

    @keyframes gradientShift {
        0%   { background-position: 0% center; }
        50%  { background-position: 100% center; }
        100% { background-position: 0% center; }
    }

    /* ============ DIVIDER ============ */
    hr {
        border-color: rgba(0, 212, 255, 0.15) !important;
        box-shadow: 0 0 6px rgba(0, 212, 255, 0.1);
    }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def render_sidebar() -> dict:
    """Render the configuration sidebar and return settings dict."""
    with st.sidebar:
        st.markdown("### 🛡️ SOC Assistant")
        st.markdown("*Offline AI-Powered Threat Detection*")
        st.divider()

        st.markdown("**⚙️ Analysis Settings**")
        log_type = st.selectbox(
            "Log Type",
            options=["auto", "ssh", "web"],
            index=0,
            help="Auto-detection works for most files.",
        )

        model = st.text_input(
            "Ollama Model",
            value=os.getenv("OLLAMA_MODEL", DEFAULT_MODEL),
            help="Model name must be installed locally.",
        )

        enable_ai = st.toggle("Enable AI Analysis", value=True)

        enable_enrich = st.toggle("Enable IP Enrichment", value=False,
                                  help="Requires ABUSEIPDB_API_KEY in .env")

        st.divider()
        st.markdown("**🔌 System Status**")

        # Ollama status
        client = OllamaClient(model=model)
        if client.is_available():
            st.success("✅ Ollama: Running")
            if client.model_is_available():
                st.success(f"✅ Model `{model}`: Ready")
            else:
                st.warning(f"⚠️ Model `{model}` not found\n\n`ollama pull {model}`")
        else:
            st.error("❌ Ollama: Offline\n\nRun `ollama serve` to enable AI")

        # AbuseIPDB status
        abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if abuseipdb_key:
            st.success("✅ AbuseIPDB: Configured")
        else:
            st.info("ℹ️ AbuseIPDB: Not configured")

        st.divider()
        st.markdown("**📂 Load Sample Logs**")

        samples_dir = Path(__file__).parent.parent / "data" / "samples"
        sample_files = list(samples_dir.glob("*.log")) if samples_dir.exists() else []

        selected_sample = st.selectbox(
            "Choose sample log",
            options=["(none)"] + [f.name for f in sample_files],
        )

        st.divider()
        st.markdown("*AI SOC Assistant v1.0*", unsafe_allow_html=False)
        st.caption("Built for cybersecurity portfolio demonstration.")

    return {
        "log_type": log_type,
        "model": model,
        "enable_ai": enable_ai,
        "enable_enrich": enable_enrich,
        "selected_sample": selected_sample,
        "samples_dir": samples_dir,
    }


# ---------------------------------------------------------------------------
# Result display sections
# ---------------------------------------------------------------------------

def render_overview_metrics(result: AnalysisResult) -> None:
    sev = result.severity
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Events Parsed", f"{result.event_count:,}")
    with col2:
        st.metric("Alerts Raised", result.alert_count)
    with col3:
        st.metric("MITRE Techniques", len(result.mitre_techniques))
    with col4:
        st.metric("Threat Score", f"{sev.score}/100")
    with col5:
        st.metric("Unique Source IPs", len(result.top_source_ips))


def render_severity_banner(result: AnalysisResult) -> None:
    sev = result.severity
    colour_map = {
        "CRITICAL": "#ff2a4b",
        "HIGH": "#ff6432",
        "MEDIUM": "#ffa500",
        "LOW": "#00ff9d",
    }
    colour = colour_map.get(sev.severity, "#ffffff")

    # 🔥 FIXED: Removed newlines and backslashes to ensure Streamlit renders HTML properly
    html = f"""<div style="background: linear-gradient(135deg, {colour}28, {colour}06), linear-gradient(180deg, rgba(10, 14, 26, 0.6), rgba(10, 14, 26, 0.9)); border: 1px solid {colour}; border-radius: 4px 20px 4px 20px; padding: 1.8rem 2rem; margin: 1rem 0; text-align: center; position: relative; overflow: hidden; box-shadow: 0 0 40px {colour}55, 0 0 80px {colour}22, inset 0 0 60px {colour}10;"><div style="position:absolute; top:0; left:0; width:80px; height:4px; background:{colour}; box-shadow:0 0 20px {colour};"></div><div style="position:absolute; top:0; right:0; width:80px; height:4px; background:{colour}; box-shadow:0 0 20px {colour};"></div><div style="position:absolute; bottom:0; left:0; width:80px; height:4px; background:{colour}; box-shadow:0 0 20px {colour};"></div><div style="position:absolute; bottom:0; right:0; width:80px; height:4px; background:{colour}; box-shadow:0 0 20px {colour};"></div><div style="font-family:'Orbitron', sans-serif; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.3em; color: #8892a4; margin-bottom: 0.7rem;">▸ Overall Severity ◂</div><div style="font-family:'Orbitron', sans-serif; font-size: 3rem; font-weight: 900; color: {colour}; letter-spacing: 0.15em; text-shadow: 0 0 30px {colour}, 0 0 60px {colour}99;">{sev.severity}</div><div style="font-family:'Rajdhani', sans-serif; font-size: 1rem; color: #c0c8d4; margin-top: 0.9rem; max-width: 700px; margin-left: auto; margin-right: auto; line-height: 1.6;">{sev.summary}</div></div>"""
    st.markdown(html, unsafe_allow_html=True)


def render_alerts(result: AnalysisResult) -> None:
    st.markdown('<div class="section-header">🚨 Rule-Based Alerts</div>', unsafe_allow_html=True)

    if not result.alerts:
        st.success("✅ No rule-based alerts triggered.")
        return

    confidence_colours = {"high": "🔴", "medium": "🟡", "low": "🟢"}
    severity_class_map = {
        "high": "alert-critical",
        "medium": "alert-medium",
        "low": "alert-low",
    }

    for alert in result.alerts:
        conf = alert.get("confidence", "low").lower()
        icon = confidence_colours.get(conf, "⚪")
        css_class = severity_class_map.get(conf, "alert-low")

        st.markdown(
            f"""<div class="{css_class}"><div style="display:flex; justify-content:space-between; align-items:center;"><span style="font-family:'Orbitron', sans-serif; font-weight:700; font-size:0.95rem; letter-spacing:0.06em;">{icon} [{alert['rule_id']}] {alert['type']}</span><span style="font-family:'JetBrains Mono', monospace; font-size:0.85rem; opacity:0.85;">{alert['source_ip']}</span></div><div style="margin-top:0.5rem; font-size:0.95rem; opacity:0.9; font-family:'Rajdhani',sans-serif;">{alert['description']}</div><div style="margin-top:0.55rem; font-size:0.75rem; opacity:0.7; font-family:'JetBrains Mono', monospace; letter-spacing:0.05em;">CONFIDENCE: <strong>{alert['confidence'].upper()}</strong>&nbsp;│&nbsp; EVENTS: <strong>{alert['affected_event_count']}</strong></div></div>""",
            unsafe_allow_html=True,
        )


def render_mitre(result: AnalysisResult) -> None:
    st.markdown('<div class="section-header">🛡️ MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)

    if not result.mitre_techniques:
        st.info("No MITRE techniques mapped.")
        return

    # Tactic grouping
    by_tactic: dict[str, list] = {}
    for tech in result.mitre_techniques:
        tactic = tech.get("tactic", "Unknown")
        by_tactic.setdefault(tactic, []).append(tech)

    for tactic, techniques in by_tactic.items():
        st.markdown(f"**{tactic}**")
        cols = st.columns(min(len(techniques), 3))
        for i, tech in enumerate(techniques):
            with cols[i % 3]:
                st.markdown(
                    f"""<div style="background:linear-gradient(135deg, rgba(0,212,255,0.08), rgba(176,38,255,0.06)); border:1px solid rgba(0,212,255,0.35); border-radius:4px 12px 4px 12px; padding:0.85rem; margin:0.3rem 0; box-shadow: 0 0 14px rgba(0,212,255,0.12); transition: all 0.2s ease;"><div style="font-family:'JetBrains Mono', monospace; color:#6fdcff; font-weight:700; font-size:1.05rem; text-shadow:0 0 8px rgba(0,212,255,0.6);">{tech['technique_id']}</div><div style="font-family:'Rajdhani',sans-serif; font-size:0.9rem; margin-top:0.35rem; color:#d8e3f0;">{tech['name']}</div><div style="font-size:0.75rem; opacity:0.7; margin-top:0.4rem; font-family:'JetBrains Mono', monospace;"><a href="{tech.get('url','#')}" target="_blank" style="color:#6fdcff; text-decoration:none;">▶ ATT&CK Reference ↗</a></div></div>""",
                    unsafe_allow_html=True,
                )
        st.markdown("")

    # Mitigations table
    with st.expander("📋 Recommended Mitigations"):
        for tech in result.mitre_techniques:
            mits = tech.get("mitigations", [])
            if mits:
                st.markdown(f"**{tech['technique_id']} — {tech['name']}**")
                for m in mits:
                    st.markdown(f"  - {m}")


def render_top_ips(result: AnalysisResult) -> None:
    st.markdown('<div class="section-header">🌐 Top Source IPs</div>', unsafe_allow_html=True)

    if not result.top_source_ips:
        st.info("No IP data available.")
        return

    rows = []

    for entry in result.top_source_ips:
        ip = entry["ip"]

        enrichment = result.ip_enrichments.get(ip)

        # Handle None properly
        if not enrichment:
            enrichment = {
                "abuseConfidenceScore": "UNKNOWN",
                "countryCode": "UNKNOWN",
                "threat_label": "UNVERIFIED"
            }

        rows.append({
            "IP Address": ip,
            "Events": entry["event_count"],
            "Event Types": ", ".join(entry.get("event_types", {}).keys()),
            "Abuse Score": enrichment.get("abuseConfidenceScore", "UNKNOWN"),
            "Country": enrichment.get("countryCode", "UNKNOWN"),
            "Threat Label": enrichment.get("threat_label", "UNKNOWN"),
        })

    import pandas as pd
    df = pd.DataFrame(rows)

    # Highlight risky IPs
    def color_row(row):
        if row["Threat Label"] in ["HIGH RISK", "KNOWN_MALICIOUS"]:
            return ["background-color: rgba(255,42,75,0.25)"] * len(row)
        elif row["Threat Label"] in ["SUSPICIOUS"]:
            return ["background-color: rgba(255,165,0,0.22)"] * len(row)
        return [""] * len(row)

    st.dataframe(df.style.apply(color_row, axis=1), use_container_width=True, hide_index=True)


def render_timeline(result: AnalysisResult) -> None:
    if not result.event_timeline:
        return

    st.markdown('<div class="section-header">📈 Event Timeline</div>', unsafe_allow_html=True)

    try:
        import pandas as pd
        timeline_data = [
            {"timestamp": t["timestamp"], "events": t["total"]}
            for t in result.event_timeline
        ]
        df = pd.DataFrame(timeline_data)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["timestamp"])
        if not df.empty:
            st.line_chart(df.set_index("timestamp")["events"])
    except Exception as exc:
        st.warning(f"Timeline chart unavailable: {exc}")


def render_ai_analysis(result: AnalysisResult) -> None:
    st.markdown('<div class="section-header">🤖 AI Analysis</div>', unsafe_allow_html=True)

    if result.ai_available:
        st.markdown(
            f"""<div style="background:linear-gradient(135deg, rgba(0,212,255,0.06), rgba(176,38,255,0.04)); border:1px solid rgba(0,212,255,0.3); border-left:4px solid #00d4ff; border-radius:4px 12px 4px 12px; padding:1.5rem; font-size:0.95rem; font-family:'Rajdhani', sans-serif; line-height:1.75; white-space:pre-wrap; color:#d8e3f0; box-shadow: 0 0 20px rgba(0,212,255,0.15), inset 0 0 40px rgba(0,212,255,0.03);">{result.ai_analysis}</div>""",
            unsafe_allow_html=True,
        )
    else:
        st.warning(result.ai_analysis)


def render_raw_report(result: AnalysisResult) -> None:
    with st.expander("📄 Full JSON Report"):
        st.json(result.to_dict())

    # Download button
    json_bytes = json.dumps(result.to_dict(), indent=2, default=str).encode("utf-8")
    st.download_button(
        label="⬇️ Download JSON Report",
        data=json_bytes,
        file_name=f"soc_report_{Path(result.file_path).stem}.json",
        mime="application/json",
    )


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

def main() -> None:
    settings = render_sidebar()

    # Header — Gaming HUD style
    st.markdown(
        """<div style="text-align:center; padding:2.2rem 0 1rem 0; position:relative;"><div style="display:inline-block; font-family:'JetBrains Mono', monospace; font-size:0.75rem; letter-spacing:0.4em; color:#6fdcff; text-transform:uppercase; margin-bottom:0.8rem; padding:0.3rem 1rem; border:1px solid rgba(0,212,255,0.35); border-radius:3px 10px 3px 10px; background:rgba(0,212,255,0.05); box-shadow:0 0 14px rgba(0,212,255,0.2);">▸ SYSTEM ONLINE ◂</div><div class="hero-title">🛡️ AI SOC ASSISTANT</div><div style="font-family:'Rajdhani', sans-serif; color:#8892a4; font-size:1.05rem; margin-top:0.8rem; letter-spacing:0.15em; text-transform:uppercase;">Offline-First · AI-Powered · Security Operations Centre</div><div style="margin-top:1rem; height:1px; background:linear-gradient(90deg, transparent, #00d4ff, #b026ff, #00d4ff, transparent); width:60%; margin-left:auto; margin-right:auto; box-shadow:0 0 12px rgba(0,212,255,0.5);"></div></div>""",
        unsafe_allow_html=True,
    )

    st.divider()

    # Upload
    uploaded_file = st.file_uploader("📤 Upload Log File", type=["log", "txt"])

    log_file_path = None
    temp_path = None

    if uploaded_file:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            tmp.write(uploaded_file.getbuffer())
            temp_path = Path(tmp.name)
            log_file_path = str(temp_path)

    if st.button("🚀 Run Analysis", disabled=log_file_path is None):

        with st.spinner("Running analysis..."):
            result = analyse_log_file(
                file_path=log_file_path,
                log_type=settings["log_type"],
                enable_ai=settings["enable_ai"],
                ollama_model=settings["model"],
            )
            st.session_state["result"] = result

        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)

    result = st.session_state.get("result")

    if result:

        st.divider()

        render_severity_banner(result)
        render_overview_metrics(result)

        # ================= SOC INTELLIGENCE BLOCK =================

        st.divider()

        # Attack Chain Summary
        st.markdown('<div class="section-header">🔗 Attack Chain Summary</div>', unsafe_allow_html=True)

        st.markdown(
            f"""<div style="background:linear-gradient(135deg, rgba(255,165,0,0.1), rgba(255,165,0,0.02)); border:1px solid rgba(255,165,0,0.35); border-left:4px solid #ffa500; border-radius:4px 12px 4px 12px; padding:1.1rem 1.3rem; font-size:0.95rem; font-family:'Rajdhani', sans-serif; line-height:1.65; color:#e6d9b8; box-shadow:0 0 18px rgba(255,165,0,0.15), inset 0 0 30px rgba(255,165,0,0.03);">{result.attack_chain_summary}</div>""",
            unsafe_allow_html=True,
        )

        # Impact Analysis
        st.markdown('<div class="section-header">⚠️ Impact Analysis</div>', unsafe_allow_html=True)

        impact = result.impact_analysis

        potential = ""
        action = ""

        if hasattr(impact, "potential_impact"):
            potential = impact.potential_impact
            action = getattr(impact, "recommended_action", "")
        elif isinstance(impact, dict):
            potential = impact.get("potential_impact", "")
            action = impact.get("recommended_action", "")

        st.markdown(
            f"""<div style="background:linear-gradient(135deg, rgba(255,42,75,0.1), rgba(255,42,75,0.02)); border:1px solid rgba(255,42,75,0.35); border-left:4px solid #ff2a4b; border-radius:4px 12px 4px 12px; padding:1.1rem 1.3rem; font-size:0.95rem; font-family:'Rajdhani', sans-serif; line-height:1.65; color:#ffd0d8; box-shadow:0 0 18px rgba(255,42,75,0.15), inset 0 0 30px rgba(255,42,75,0.03);">{potential}</div>""",
            unsafe_allow_html=True,
        )

        if action:
            st.markdown("### 🛠️ Recommended Action")
            st.success(action)

        # ================= END SOC INTELLIGENCE BLOCK =================

        st.divider()

        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "🚨 Alerts",
            "🛡️ MITRE ATT&CK",
            "🌐 Source IPs",
            "📈 Timeline",
            "🤖 AI Analysis",
            "📄 Raw Report",
        ])

        with tab1:
            render_alerts(result)

        with tab2:
            render_mitre(result)

        with tab3:
            render_top_ips(result)

        with tab4:
            render_timeline(result)

        with tab5:
            render_ai_analysis(result)

        with tab6:
            render_raw_report(result)

        # Save report
        output_dir = Path("outputs/reports")
        try:
            report_path = save_report(result, output_dir)
            st.caption(f"📁 Report auto-saved: `{report_path}`")
        except Exception as exc:
            logger.warning("Could not save report: %s", exc)

    else:
        st.markdown(
            """<div style="text-align:center; padding:4rem 2rem; opacity:0.7;"><div style="font-size:5rem; filter: drop-shadow(0 0 24px rgba(0,212,255,0.6)); animation: flicker 3s infinite;">🔍</div><div style="font-family:'Orbitron', sans-serif; font-size:1rem; margin-top:1.5rem; letter-spacing:0.2em; color:#6fdcff; text-transform:uppercase; text-shadow:0 0 12px rgba(0,212,255,0.5);">▸ Awaiting Input Stream ◂</div><div style="font-family:'Rajdhani', sans-serif; font-size:1rem; margin-top:0.6rem; color:#8892a4;">Upload a log file to initiate threat analysis</div></div>""",
            unsafe_allow_html=True,
        )


if __name__ == "__main__":
    main()