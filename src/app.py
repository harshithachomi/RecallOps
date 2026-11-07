"""
RecallOps – AI Incident Response & Prevention Agent
Final UI Alignment, Color & Sidebar Correction
Enterprise cybersecurity SaaS dashboard matching MedTrack visual standards:
- Dark navy sidebar (#071C2B) with active navigation (#087FA3) and NO radio button circles
- Compact, professional SYSTEM STATUS panel at bottom of sidebar (no emojis, dynamic values)
- Clean light workspace (#F3F7FA) with white cards (#FFFFFF) and subtle borders (#DCE5ED)
- High-contrast typography: Headings (#172B3A), Labels/Text (#263746), Metadata (#526777)
- White inputs with dark navy text (#172B3A) and dark navy dropdown popovers with white option text (#FFFFFF)
- Plotly charts with light background (#FFFFFF), dark titles/labels (#172B3A), and soft gridlines (#DCE5ED)
- 10-item sidebar navigation (System Health and Configuration removed as requested)
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
import sys
import os
import json
from pathlib import Path

# Add project root and src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = Path(__file__).resolve().parent
for p in [str(PROJECT_ROOT), str(SRC_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Import core modular backend components
from database import get_database_engine
from incident_manager import (
    create_incident,
    get_incident,
    list_incidents,
    get_incident_statistics,
    get_feedback_analytics,
    update_incident_resolution
)
from log_processor import parse_log_payload, parse_csv_logs
from incident_detector import detect_and_classify_incident, CATEGORIES
from root_cause_analyzer import investigate_incident
from hindsight_memory import (
    recall_incident_memories,
    retain_incident_memory,
    get_local_memory_cache,
    check_hindsight_cloud_status,
    get_memory_status
)
from feedback_manager import record_developer_feedback
from prevention_engine import generate_prevention_insights
from dataset_evaluator import evaluate_hdfs_detection, evaluate_swebench_retrieval, get_full_evaluation_report
from ai_agent import ask_agent, save_feedback

# Initialize database schema and auto-migrations
get_database_engine()

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(
    page_title="RecallOps – AI Incident Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------------------------------------------------
# Dataset Loading
# ---------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_datasets():
    base_dirs = [Path("."), PROJECT_ROOT, SRC_DIR]
    hdfs_path = None
    swe_path = None
    for b in base_dirs:
        hp = b / "processed_data" / "hdfs_clean.csv"
        sp = b / "processed_data" / "swebench_clean.csv"
        if hp.exists() and sp.exists():
            hdfs_path = hp
            swe_path = sp
            break
    if hdfs_path is None:
        hdfs_path = Path("processed_data/hdfs_clean.csv")
        swe_path = Path("processed_data/swebench_clean.csv")

    hdfs = pd.read_csv(hdfs_path)
    swe = pd.read_csv(swe_path)
    return hdfs, swe

hdfs_df, swe_df = load_datasets()

# Precompute dataset metrics
total_logs = len(hdfs_df)
warn_logs = int((hdfs_df["Level"] == "WARN").sum())
info_logs = int((hdfs_df["Level"] == "INFO").sum())
total_issues = len(swe_df)
resolved_issues = len(swe_df[swe_df["patch"].notna() & (swe_df["patch"].astype(str).str.strip() != "")])
repo_counts = swe_df["repo"].value_counts().head(8)
log_counts = hdfs_df["Level"].value_counts()
event_counts = hdfs_df["EventTemplate"].value_counts()
rare_events = event_counts[event_counts <= 2]

# TF-IDF Vectorizer for SWE issues
@st.cache_resource(show_spinner=False)
def get_swe_vectorizer(df):
    from sklearn.feature_extraction.text import TfidfVectorizer
    df_clean = df.copy()
    df_clean["issue_text"] = df_clean["issue_text"].fillna("")
    df_clean = df_clean[df_clean["issue_text"].str.strip() != ""].copy()
    vectorizer = TfidfVectorizer(stop_words="english", max_features=5000)
    tfidf_matrix = vectorizer.fit_transform(df_clean["issue_text"])
    return vectorizer, tfidf_matrix, df_clean

swe_vectorizer, swe_tfidf_matrix, swe_search_df = get_swe_vectorizer(swe_df)

# ---------------------------------------------------------
# Streamlit Global Stylesheet (Enterprise SaaS Architecture)
# ---------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
}

/* Eliminate Streamlit's native header gap & black band */
header[data-testid="stHeader"] {
    display: none !important;
}

/* Prevent horizontal overflow across the entire application */
html, body {
    overflow-x: hidden !important;
    max-width: 100vw !important;
    box-sizing: border-box !important;
}

*, *:before, *:after {
    box-sizing: border-box !important;
}

/* Light Workspace Background */
.stApp {
    background-color: #F3F7FA !important;
    color: #172B3A !important;
    overflow-x: hidden !important;
    max-width: 100vw !important;
}

/* Page Container Padding & Starting Position */
.block-container {
    padding-top: 1.25rem !important;
    padding-bottom: 2.5rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 100% !important;
    overflow-x: hidden !important;
    box-sizing: border-box !important;
}

/* Dark Navy Sidebar */
[data-testid="stSidebar"] {
    background-color: #071C2B !important;
    border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
    width: 275px !important;
    min-width: 275px !important;
}

[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {
    padding-top: 0.85rem !important;
    padding-left: 0.85rem !important;
    padding-right: 0.85rem !important;
    box-sizing: border-box !important;
}

/* Remove ALL radio circular indicators in the sidebar navigation */
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] > div > div:first-child,
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] > label > div:first-child,
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] div:first-child:not(:last-child),
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] input,
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] svg,
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] [class*="key4"],
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] [class*="key5"],
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] label > div:first-child {
    display: none !important;
    width: 0 !important;
    height: 0 !important;
    min-width: 0 !important;
    max-width: 0 !important;
    opacity: 0 !important;
    visibility: hidden !important;
    margin: 0 !important;
    padding: 0 !important;
    border: none !important;
    background: transparent !important;
}

/* Sidebar Navigation Items - No wrapping, clean alignment */
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"],
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] label {
    padding: 7px 12px !important;
    border-radius: 6px !important;
    margin-bottom: 3px !important;
    cursor: pointer !important;
    display: flex !important;
    align-items: center !important;
    width: 100% !important;
    box-sizing: border-box !important;
    transition: background-color 0.15s ease, color 0.15s ease !important;
    white-space: nowrap !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:hover,
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] label:hover {
    background: rgba(255, 255, 255, 0.06) !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:hover p,
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] label:hover p {
    color: #FFFFFF !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"][aria-checked="true"],
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:has([aria-checked="true"]),
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:has(input:checked),
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] [aria-checked="true"] {
    background: #087FA3 !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"][aria-checked="true"] p,
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:has([aria-checked="true"]) p,
[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:has(input:checked) p,
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] [aria-checked="true"] p {
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] p,
[data-testid="stSidebar"] [data-testid="stRadio"] [role="radiogroup"] label p {
    color: #B5C4CE !important;
    font-size: 0.84rem !important;
    font-weight: 500 !important;
    margin: 0 !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}

/* Typography Hierarchy */
h1 {
    color: #172B3A !important;
    font-size: 1.75rem !important;
    font-weight: 700 !important;
    line-height: 1.25 !important;
    letter-spacing: -0.02em !important;
}

h2 {
    color: #172B3A !important;
    font-size: 1.3rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.01em !important;
}

h3 {
    color: #172B3A !important;
    font-size: 1.05rem !important;
    font-weight: 700 !important;
}

h4 {
    color: #172B3A !important;
    font-size: 0.95rem !important;
    font-weight: 700 !important;
}

p, span, label, div {
    color: #263746;
}

/* Enterprise White Cards */
.med-card {
    background-color: #FFFFFF;
    border: 1px solid #DCE5ED;
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 16px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    box-sizing: border-box;
}

/* Responsive CSS Grid for 6 Summary Cards */
.summary-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    width: 100%;
    margin-bottom: 18px;
    box-sizing: border-box;
}

@media (max-width: 1400px) {
    .summary-grid {
        grid-template-columns: repeat(3, 1fr);
    }
}

@media (max-width: 768px) {
    .summary-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

/* Summary Metric Card */
.summary-card {
    background-color: #FFFFFF;
    border: 1px solid #DCE5ED;
    border-radius: 8px;
    padding: 14px 16px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    min-height: 106px;
    height: 100%;
    box-sizing: border-box;
}

.summary-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
}

.summary-title {
    font-size: 0.74rem;
    font-weight: 700;
    color: #263746;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.summary-icon-box {
    width: 26px;
    height: 26px;
    border-radius: 5px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.summary-value {
    font-size: 1.65rem;
    font-weight: 800;
    color: #172B3A;
    line-height: 1.2;
    letter-spacing: -0.02em;
}

.summary-subtext {
    font-size: 0.74rem;
    font-weight: 600;
    color: #526777;
    margin-top: 4px;
    display: flex;
    align-items: center;
    gap: 4px;
}

/* Top Navigation Bar */
.topbar-wrapper {
    background-color: #FFFFFF;
    border: 1px solid #DCE5ED;
    border-radius: 8px;
    padding: 12px 18px;
    margin-bottom: 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
    box-sizing: border-box;
}

.topbar-title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #172B3A;
    margin: 0;
    line-height: 1.2;
}

.topbar-subtitle {
    font-size: 0.82rem;
    color: #526777;
    margin-top: 2px;
}

.topbar-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #F8FAFC;
    border: 1px solid #DCE5ED;
    border-radius: 5px;
    padding: 5px 10px;
    font-size: 0.74rem;
    font-weight: 600;
}

/* Compact Enterprise Sidebar Status Panel */
.sidebar-status-panel {
    background: rgba(5, 20, 32, 0.75);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    padding: 8px 10px;
    margin-top: 18px;
    font-size: 0.72rem;
}

.status-panel-title {
    font-size: 0.65rem;
    font-weight: 700;
    color: #7E93A3;
    letter-spacing: 0.08em;
    margin-bottom: 6px;
    text-transform: uppercase;
}

.status-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
    line-height: 1.25;
}

.status-row:last-child {
    margin-bottom: 0;
}

.status-label {
    color: #B5C4CE;
    font-size: 0.72rem;
}

.status-value {
    color: #FFFFFF;
    font-weight: 600;
    font-size: 0.72rem;
    font-family: 'JetBrains Mono', monospace;
    display: flex;
    align-items: center;
    gap: 5px;
}

.status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    display: inline-block;
}

/* Severity & Indicator Badges */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    text-transform: uppercase;
}

.badge-critical { background-color: #FEE2E2; color: #E5485D !important; border: 1px solid #FECACA; }
.badge-high { background-color: #FEF3C7; color: #D97706 !important; border: 1px solid #FDE68A; }
.badge-medium { background-color: #E0F2FE; color: #078EBB !important; border: 1px solid #BAE6FD; }
.badge-low { background-color: #DCFCE7; color: #17A878 !important; border: 1px solid #BBF7D0; }
.badge-info { background-color: #F1F5F9; color: #172B3A !important; border: 1px solid #DCE5ED; }
.badge-success { background-color: #E6F8F3; color: #065F46 !important; border: 1px solid #B8EBDD; }

/* Primary Action Buttons */
.stButton>button {
    background: #087FA3 !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
    border: none !important;
    border-radius: 6px !important;
    padding: 8px 16px !important;
    font-size: 0.86rem !important;
    transition: background 0.15s ease !important;
    box-shadow: 0 1px 2px rgba(8, 127, 163, 0.2) !important;
}

.stButton>button:hover {
    background: #066683 !important;
    box-shadow: 0 2px 5px rgba(8, 127, 163, 0.3) !important;
}

/* Input Fields (White background with dark navy text) */
.stTextInput input,
.stTextArea textarea,
.stNumberInput input {
    background-color: #FFFFFF !important;
    color: #172B3A !important;
    border: 1px solid #D5E0E9 !important;
    border-radius: 6px !important;
    font-size: 0.86rem !important;
    font-family: 'Plus Jakarta Sans', sans-serif !important;
}

.stTextInput input::placeholder,
.stTextArea textarea::placeholder {
    color: #758493 !important;
    opacity: 1 !important;
}

.stTextInput input:focus,
.stTextArea textarea:focus,
.stNumberInput input:focus {
    border-color: #078EBB !important;
    box-shadow: 0 0 0 1px #078EBB !important;
    outline: none !important;
}

/* Input & Form Labels */
.stTextInput label,
.stTextArea label,
.stSelectbox label,
.stRadio label,
.stNumberInput label {
    color: #172B3A !important;
    font-size: 0.84rem !important;
    font-weight: 600 !important;
    margin-bottom: 4px !important;
}

.stTextInput label p,
.stTextArea label p,
.stSelectbox label p,
.stRadio label p {
    color: #172B3A !important;
    font-size: 0.84rem !important;
    font-weight: 600 !important;
}

/* Closed Dropdown (Selectbox): White background, dark navy text & dark arrow */
div[data-baseweb="select"] > div {
    background-color: #FFFFFF !important;
    border: 1px solid #D5E0E9 !important;
    border-radius: 6px !important;
    color: #172B3A !important;
}

div[data-baseweb="select"] * {
    color: #172B3A !important;
}

div[data-baseweb="select"] svg {
    fill: #172B3A !important;
    color: #172B3A !important;
}

div[data-baseweb="select"]:hover > div {
    border-color: #087FA3 !important;
}

/* Opened Dropdown Menu (Popover List): Dark Navy background (#071C2B), White text (#FFFFFF) */
div[data-baseweb="popover"],
div[data-baseweb="popover"] > div,
div[data-baseweb="popover"] ul,
ul[role="listbox"],
ul[data-baseweb="menu"] {
    background-color: #071C2B !important;
    border: 1px solid #1E3A52 !important;
    border-radius: 6px !important;
}

li[role="option"],
li[data-baseweb="menu-item"],
div[data-baseweb="popover"] li,
div[data-baseweb="popover"] li * {
    background-color: #071C2B !important;
    color: #FFFFFF !important;
    font-size: 0.85rem !important;
}

li[role="option"]:hover,
li[role="option"]:hover *,
div[data-baseweb="popover"] li:hover,
div[data-baseweb="popover"] li:hover * {
    background-color: #0D2E45 !important;
    color: #FFFFFF !important;
}

li[role="option"][aria-selected="true"],
li[role="option"][aria-selected="true"] *,
div[data-baseweb="popover"] li[aria-selected="true"],
div[data-baseweb="popover"] li[aria-selected="true"] * {
    background-color: #087FA3 !important;
    color: #FFFFFF !important;
    font-weight: 600 !important;
}

/* DataFrames & Tables */
[data-testid="stDataFrame"], [data-testid="stTable"] {
    background-color: #FFFFFF !important;
    border: 1px solid #DCE5ED !important;
    border-radius: 8px !important;
    box-shadow: 0 1px 2px rgba(0,0,0,0.02) !important;
}

[data-testid="stDataFrame"] [data-testid="glide-data-grid"] {
    background-color: #FFFFFF !important;
}

[data-testid="stDataFrame"] * {
    color: #172B3A !important;
}

/* Suppress floating element toolbar (search/fullscreen overlay) */
[data-testid="stElementToolbar"] {
    display: none !important;
}



/* Code Blocks */
code, pre {
    font-family: 'JetBrains Mono', monospace !important;
    background: #F8FAFC !important;
    color: #0369A1 !important;
    border: 1px solid #DCE5ED !important;
    border-radius: 6px !important;
    font-size: 0.8rem !important;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# Sidebar Component (Clean Enterprise Dark Navy)
# ---------------------------------------------------------
with st.sidebar:
    # Sidebar Brand Header with Cybersecurity Shield
    st.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; padding: 10px 2px 14px 2px; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 12px;">
        <div style="width: 34px; height: 34px; border-radius: 6px; background: #087FA3; display: flex; align-items: center; justify-content: center;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                <path d="M12 8v4"></path>
                <path d="M12 16h.01"></path>
            </svg>
        </div>
        <div>
            <div style="font-size: 1.1rem; font-weight: 800; color: #FFFFFF; letter-spacing: -0.01em;">RECALLOPS</div>
            <div style="font-size: 0.64rem; color: #13B8CF; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em;">AI Incident Intelligence</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 10 Clean Sidebar Navigation Items (System Health & Configuration removed)
    nav_selection = st.radio(
        "Navigation",
        [
            "📊 Dashboard",
            "📋 All Incidents",
            "🚀 New Investigation",
            "🔬 Root Cause Analysis",
            "📜 Incident History",
            "🧠 Hindsight Memory",
            "💡 Similar Experiences",
            "🛡️ Prevention Center",
            "📈 Analytics & Reports",
            "💬 Developer Feedback"
        ],
        label_visibility="collapsed"
    )

    # Compact Enterprise SYSTEM STATUS Panel
    mem_sys_status = get_memory_status()
    db_stats = get_incident_statistics()
    is_cloud = mem_sys_status["cloud_status"]["connected"]
    service_status_text = "Connected" if is_cloud else "Local fallback"
    dot_color = "#17A878" if is_cloud else "#087FA3"

    st.markdown(f"""
    <div class="sidebar-status-panel">
        <div class="status-panel-title">SYSTEM STATUS</div>
        <div class="status-row">
            <span class="status-label">Memory Service</span>
            <span class="status-value"><span class="status-dot" style="background-color: {dot_color};"></span>{service_status_text}</span>
        </div>
        <div class="status-row">
            <span class="status-label">Stored Experiences</span>
            <span class="status-value">{db_stats['total_stored_incidents']}</span>
        </div>
        <div class="status-row">
            <span class="status-label">Verified Resolutions</span>
            <span class="status-value">{db_stats['resolved_incidents']}</span>
        </div>
    </div>
    <div style="text-align: center; margin-top: 10px; font-size: 0.68rem; color: #7E93A3;">
        RecallOps Enterprise • v2.5
    </div>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------
# Top Navigation Bar Helper
# ---------------------------------------------------------
def render_topbar(title: str, subtitle: str):
    mem_info = get_memory_status()
    is_cloud = mem_info["cloud_status"]["connected"]
    mem_label = "Hindsight: Connected" if is_cloud else "Hindsight: Local fallback"
    mem_color = "#17A878" if is_cloud else "#087FA3"

    st.markdown(f"""
    <div class="topbar-wrapper">
        <div>
            <h1 class="topbar-title">{title}</h1>
            <div class="topbar-subtitle">{subtitle}</div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
            <div class="topbar-badge" style="color: #17A878;">
                <span class="status-dot" style="background-color: #17A878;"></span> System Healthy
            </div>
            <div class="topbar-badge" style="color: {mem_color};">
                <span class="status-dot" style="background-color: {mem_color};"></span> {mem_label}
            </div>
            <div class="topbar-badge" style="color: #172B3A; background: #EAF2F8; font-family: 'JetBrains Mono', monospace;">
                SecOps • Admin
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


# =========================================================
# 1. DASHBOARD OVERVIEW PAGE
# =========================================================
if nav_selection == "📊 Dashboard":
    render_topbar(
        "Dashboard Overview",
        "Monitor incidents, investigate root causes and learn from previous experiences."
    )

    db_stats = get_incident_statistics()
    fb_analytics = get_feedback_analytics()

    total_incidents = total_logs + total_issues + db_stats["total_stored_incidents"]
    active_pending = warn_logs + db_stats["pending_incidents"]
    resolved_count = resolved_issues + db_stats["resolved_incidents"]
    recurring_count = len(rare_events) + 2
    critical_count = db_stats["critical_incidents"]
    success_rate = fb_analytics["resolution_success_rate"]

    # 6 Summary Metric Cards (Responsive CSS Grid)
    st.markdown(f"""
    <div class="summary-grid">
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Total Incidents</span>
                <div class="summary-icon-box" style="background: #E0F2FE; color: #078EBB;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
                </div>
            </div>
            <div class="summary-value">{total_incidents:,}</div>
            <div class="summary-subtext"><span style="color: #078EBB; font-weight:700;">↑ All telemetry</span> sources</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Active / Pending</span>
                <div class="summary-icon-box" style="background: #FEF3C7; color: #D97706;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                </div>
            </div>
            <div class="summary-value">{active_pending:,}</div>
            <div class="summary-subtext"><span style="color: #D97706; font-weight:700;">Requires</span> review</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Resolved</span>
                <div class="summary-icon-box" style="background: #DCFCE7; color: #17A878;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>
                </div>
            </div>
            <div class="summary-value">{resolved_count:,}</div>
            <div class="summary-subtext"><span style="color: #17A878; font-weight:700;">Verified</span> fixes</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Recurring</span>
                <div class="summary-icon-box" style="background: #F3E8FF; color: #7C3AED;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
                </div>
            </div>
            <div class="summary-value">{recurring_count}</div>
            <div class="summary-subtext"><span style="color: #7C3AED; font-weight:700;">Pattern</span> recurrence</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Critical</span>
                <div class="summary-icon-box" style="background: #FEE2E2; color: #E5485D;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                </div>
            </div>
            <div class="summary-value">{critical_count}</div>
            <div class="summary-subtext"><span style="color: #E5485D; font-weight:700;">High priority</span> outages</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Success Rate</span>
                <div class="summary-icon-box" style="background: #E6F8F3; color: #17A878;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"></polyline><polyline points="17 6 23 6 23 12"></polyline></svg>
                </div>
            </div>
            <div class="summary-value">{success_rate}%</div>
            <div class="summary-subtext"><span style="color: #17A878; font-weight:700;">Verified</span> adoption</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Main Sections: LEFT Recent Detected Incidents (~62%), RIGHT Hindsight Memory Status (~38%)
    sec_left, sec_right = st.columns([1.65, 1.0])

    with sec_left:
        st.markdown("""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <h3 style="margin: 0; font-size: 0.98rem; color: #172B3A; font-weight: 700;">Recent Detected Incidents</h3>
            <span class="badge badge-info" style="font-size: 0.68rem;">LIVE ACTIVITY</span>
        </div>
        """, unsafe_allow_html=True)

        recent_incidents = list_incidents(limit=5)
        if recent_incidents:
            df_recent = pd.DataFrame([{
                "Incident ID": inc["incident_id"],
                "Error Category": inc["error_category"],
                "Severity": inc["severity"],
                "Status": inc["resolution_status"].split(" - ")[0] if " - " in str(inc.get("resolution_status", "")) else str(inc.get("resolution_status", "Pending")),
                "Detection Time": inc["created_at"].split("T")[0] if "T" in str(inc["created_at"]) else str(inc["created_at"])[:10]
            } for inc in recent_incidents])

            st.dataframe(
                df_recent,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Incident ID": st.column_config.TextColumn("Incident ID", width="small"),
                    "Error Category": st.column_config.TextColumn("Error Category", width="medium"),
                    "Severity": st.column_config.TextColumn("Severity", width="small"),
                    "Status": st.column_config.TextColumn("Status", width="small"),
                    "Detection Time": st.column_config.TextColumn("Date", width="small")
                }
            )
        else:
            st.info("No live incidents recorded yet. Use '🚀 New Investigation' to analyze your first log.")

    with sec_right:
        mem_info = get_memory_status()
        cloud_active = mem_info["cloud_status"]["connected"]
        cloud_badge = "badge-success" if cloud_active else "badge-medium"
        cloud_label = "CLOUD SYNCHRONIZED" if cloud_active else "LOCAL FALLBACK"
        conn_msg = mem_info['cloud_status']['message']
        if len(conn_msg) > 60:
            conn_msg = conn_msg[:60] + "..."

        st.markdown(f"""
        <div class="med-card" style="padding: 16px 18px; margin-bottom: 0;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; gap: 6px;">
                <h3 style="margin: 0; font-size: 0.98rem; color: #172B3A; font-weight: 700; white-space: nowrap;">Hindsight Memory Status</h3>
                <span class="badge {cloud_badge}" style="font-size: 0.68rem; white-space: nowrap;">{cloud_label}</span>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px 12px; border-radius: 6px; box-sizing: border-box; min-width: 0;">
                    <div style="font-size: 0.68rem; color: #263746; font-weight: 700; text-transform: uppercase; white-space: nowrap;">Retained Experiences</div>
                    <div style="font-size: 1.35rem; font-weight: 800; color: #172B3A; margin-top: 2px;">{mem_info['local_cache_count']}</div>
                </div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px 12px; border-radius: 6px; box-sizing: border-box; min-width: 0;">
                    <div style="font-size: 0.68rem; color: #263746; font-weight: 700; text-transform: uppercase; white-space: nowrap;">Verified Fixes</div>
                    <div style="font-size: 1.35rem; font-weight: 800; color: #17A878; margin-top: 2px;">{mem_info['verified_solutions_count']}</div>
                </div>
            </div>
            <div style="font-size: 0.78rem; color: #263746; line-height: 1.45; word-break: break-word; overflow-wrap: anywhere;">
                <div style="margin-bottom: 4px;"><strong>Active Bank:</strong> <code style="color:#0369A1; word-break: break-all;">incident-intelligence</code></div>
                <div style="word-break: break-word; overflow-wrap: anywhere;"><strong>Connection:</strong> <span style="color:#172B3A;">{conn_msg}</span></div>
            </div>
            <div style="font-size: 0.72rem; color: #526777; border-top: 1px solid #DCE5ED; padding-top: 8px; margin-top: 10px;">
                Verified human feedback improves future AI root cause recommendations.
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)

    # Visual Analytics Row
    ch1, ch2 = st.columns(2)
    with ch1:
        st.markdown("""
        <div class="med-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <h3 style="margin: 0; font-size: 1rem; color: #172B3A;">Cluster Log Severity Ratio</h3>
                <span class="badge badge-info">HDFS Telemetry</span>
            </div>
        """, unsafe_allow_html=True)

        fig_pie = px.pie(
            pd.DataFrame({"Severity": log_counts.index, "Count": log_counts.values}),
            names="Severity",
            values="Count",
            hole=0.6,
            color="Severity",
            color_discrete_map={"INFO": "#078EBB", "WARN": "#E9A23B"}
        )
        fig_pie.update_layout(
            template="plotly_white",
            paper_bgcolor="#FFFFFF",
            plot_bgcolor="#FFFFFF",
            margin=dict(t=10, b=10, l=10, r=10),
            height=240,
            font=dict(family="Plus Jakarta Sans", size=12, color="#172B3A"),
            legend=dict(
                orientation="h",
                y=-0.15,
                x=0.5,
                xanchor="center",
                font=dict(color="#172B3A", size=11)
            )
        )
        st.plotly_chart(fig_pie, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with ch2:
        st.markdown("""
        <div class="med-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <h3 style="margin: 0; font-size: 1rem; color: #172B3A;">Defect Volume by Repository</h3>
                <span class="badge badge-medium">SWE-bench Knowledge</span>
            </div>
        """, unsafe_allow_html=True)

        fig_bar = px.bar(
            pd.DataFrame({"Repository": repo_counts.index, "Issues": repo_counts.values}),
            x="Issues",
            y="Repository",
            orientation="h",
            color="Issues",
            color_continuous_scale=["#078EBB", "#13B8CF", "#6366F1"],
            text="Issues"
        )
        fig_bar.update_layout(
            template="plotly_white",
            paper_bgcolor="#FFFFFF",
            plot_bgcolor="#FFFFFF",
            margin=dict(t=10, b=10, l=10, r=10),
            height=240,
            font=dict(family="Plus Jakarta Sans", size=12, color="#172B3A"),
            xaxis=dict(
                title=dict(text="", font=dict(color="#172B3A")),
                tickfont=dict(color="#263746", size=10),
                gridcolor="#DCE5ED"
            ),
            yaxis=dict(
                title=dict(text="", font=dict(color="#172B3A")),
                tickfont=dict(color="#263746", size=10),
                categoryorder="total ascending"
            ),
            coloraxis_showscale=False
        )
        st.plotly_chart(fig_bar, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# 2. INCIDENT MANAGEMENT PAGE (ALL INCIDENTS)
# =========================================================
elif nav_selection == "📋 All Incidents":
    render_topbar(
        "Incident Management",
        "Monitor, investigate and manage detected incidents across all services and infrastructure."
    )

    st.markdown("""
    <div class="med-card" style="padding: 14px 18px; margin-bottom: 14px;">
        <h3 style="font-size: 0.95rem; margin-top: 0; margin-bottom: 10px; color: #172B3A;">Search & Filter Incidents</h3>
    """, unsafe_allow_html=True)

    f_col1, f_col2, f_col3, f_col4 = st.columns([1.4, 1, 1, 1])
    with f_col1:
        search_kw = st.text_input("Search Keyword", placeholder="Search by ID, error message, or component...")
    with f_col2:
        cat_filter = st.selectbox("Error Category", ["ALL"] + CATEGORIES)
    with f_col3:
        sev_filter = st.selectbox("Severity Level", ["ALL", "Critical", "High", "Medium", "Low", "Informational"])
    with f_col4:
        status_filter = st.selectbox("Resolution Status", [
            "ALL",
            "Pending Investigation",
            "Resolved - Verified Fix",
            "Resolved - Alternative Fix",
            "Partially Resolved - Needs Tuning",
            "Root Cause Disputed - Reopened",
            "Unsuccessful - Needs Investigation"
        ])

    st.markdown("</div>", unsafe_allow_html=True)

    all_records = list_incidents(
        category=cat_filter,
        severity=sev_filter,
        status=status_filter,
        search=search_kw,
        limit=100
    )

    st.markdown(f"""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
        <span style="font-size: 0.82rem; font-weight: 700; color: #263746;">Showing {len(all_records)} recorded incidents</span>
    </div>
    """, unsafe_allow_html=True)

    if all_records:
        formatted_table = []
        for r in all_records:
            formatted_table.append({
                "Incident ID": r["incident_id"],
                "Error Summary": r["error_message"][:75] + ("..." if len(r["error_message"]) > 75 else ""),
                "Category": r["error_category"],
                "Severity": r["severity"],
                "Component": r.get("component") or "Core",
                "Status": r["resolution_status"],
                "Created At": r["created_at"].split("T")[0] if "T" in str(r["created_at"]) else str(r["created_at"])[:10]
            })
        st.dataframe(pd.DataFrame(formatted_table), use_container_width=True, hide_index=True)

        st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

        st.markdown("""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 0.95rem; color: #172B3A;">Quick Inspection</h3>
        """, unsafe_allow_html=True)

        sel_id = st.selectbox("Select Incident to Inspect", [r["incident_id"] for r in all_records])
        selected_rec = next(r for r in all_records if r["incident_id"] == sel_id)

        sev_class = "badge-critical" if selected_rec["severity"] == "Critical" else "badge-high" if selected_rec["severity"] == "High" else "badge-medium"

        st.markdown(f"""
        <div style="background: #FFFFFF; border: 1px solid #DCE5ED; border-radius: 6px; padding: 14px; margin-top: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 0.95rem; font-weight: 700; color: #087FA3; font-family: 'JetBrains Mono', monospace;">{selected_rec['incident_id']}</span>
                <span class="badge {sev_class}">{selected_rec['severity']}</span>
            </div>
            <div style="font-size: 0.88rem; color: #172B3A; font-weight: 700; margin-bottom: 6px;">{selected_rec['error_message']}</div>
            <div style="font-size: 0.78rem; color: #526777; margin-bottom: 8px;">
                Category: <strong style="color:#172B3A;">{selected_rec['error_category']}</strong> • Component: <strong style="color:#172B3A;">{selected_rec.get('component') or 'ApplicationCore'}</strong> • Status: <strong style="color:#172B3A;">{selected_rec['resolution_status']}</strong>
            </div>
            <div style="font-size: 0.82rem; color: #263746; background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                <strong>Suspected Root Cause:</strong> {selected_rec.get('possible_root_cause') or 'Pending investigation'}
            </div>
            {f"<div style='font-size: 0.82rem; color: #065F46; font-weight:600; margin-top: 8px;'>Applied Solution: {selected_rec.get('applied_solution')}</div>" if selected_rec.get('applied_solution') else ""}
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No incidents found matching the filter criteria.")


# =========================================================
# 3. NEW INVESTIGATION PAGE
# =========================================================
elif nav_selection == "🚀 New Investigation":
    render_topbar(
        "New Investigation",
        "Analyze software failure logs, classify errors, recall memories and investigate root causes."
    )

    st.markdown("""
    <div class="med-card">
        <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Incident Ingestion Workspace</h3>
        <p style="font-size: 0.82rem; color: #526777; margin-bottom: 14px;">
            Select a verified demonstration log preset or paste your raw error log / stack trace.
        </p>
    """, unsafe_allow_html=True)

    mode_choice = st.radio("Ingestion Mode", ["Demo Sample Presets", "Paste Log / Stack Trace", "Upload Log File"], horizontal=True)

    raw_input_text = ""
    demo_files = {
        "Demo 1: Database Connection Timeout (Initial Occurrence)": "demo_samples/sample1_database_timeout_initial.log",
        "Demo 2: Database Connection Timeout (Recurring Occurrence)": "demo_samples/sample2_database_timeout_recurrence.log",
        "Demo 3: Java Heap OutOfMemoryError & Container OOMKilled": "demo_samples/sample3_memory_oomkill.log",
        "Demo 4: JWT Expired & Authentication Failure Cascade": "demo_samples/sample4_authentication_jwt_expired.log",
        "Demo 5: Clean Log / Edge Case Validation": "demo_samples/sample5_empty.log"
    }

    if mode_choice == "Demo Sample Presets":
        selected_demo_name = st.selectbox("Select Demo Scenario", list(demo_files.keys()))
        sample_path = PROJECT_ROOT / demo_files[selected_demo_name]
        if sample_path.exists():
            with open(sample_path, "r", encoding="utf-8") as f:
                raw_input_text = f.read()
    elif mode_choice == "Paste Log / Stack Trace":
        raw_input_text = st.text_area(
            "Paste Error Log, Stack Trace, or Telemetry Line",
            height=140,
            placeholder="Paste your software error log or incident stack trace here..."
        )
    else:
        uploaded_file = st.file_uploader("Upload Log File (.log, .txt, .json, .csv)", type=["log", "txt", "json", "csv"])
        if uploaded_file is not None:
            raw_input_text = uploaded_file.read().decode("utf-8", errors="replace")

    with st.expander("Preview Ingestion Payload", expanded=False):
        st.code(raw_input_text if raw_input_text else "Payload is empty.")

    btn_investigate = st.button("Analyze Incident with RecallOps", type="primary")
    st.markdown("</div>", unsafe_allow_html=True)

    if btn_investigate:
        if not raw_input_text.strip():
            st.warning("Please provide a log payload or select a demo sample to investigate.")
        else:
            with st.spinner("Classifying failure signature and querying Hindsight memory banks..."):
                det = detect_and_classify_incident(raw_input_text)
                recalled = recall_incident_memories(
                    query=f"{det['error_category']} {det['error_message']}",
                    domain="incidents",
                    top_k=3
                )
                inv = investigate_incident(
                    error_message=det["error_message"],
                    error_category=det["error_category"],
                    severity=det["severity"],
                    original_log=raw_input_text,
                    evidence=det["detected_evidence"],
                    retrieved_memories=recalled,
                    component=det["component"]
                )
                saved = create_incident(
                    original_log=raw_input_text,
                    error_message=det["error_message"],
                    error_category=det["error_category"],
                    severity=det["severity"],
                    detected_evidence=det["detected_evidence"],
                    possible_root_cause=inv.get("possible_root_cause"),
                    root_cause_confidence=inv.get("root_cause_confidence", "Likely"),
                    ai_explanation=inv.get("explanation"),
                    recommended_solution=inv.get("recommended_solutions"),
                    recommendations_count=len(inv.get("recommended_solutions", [])),
                    memory_source_used=recalled[0].get("source_type") if recalled else "None",
                    component=det["component"]
                )

                st.session_state["active_incident"] = saved
                st.session_state["active_investigation"] = inv
                st.session_state["active_recalled_memories"] = recalled

    # Display Active Investigation Results
    if "active_incident" in st.session_state and "active_investigation" in st.session_state:
        inc = st.session_state["active_incident"]
        inv = st.session_state["active_investigation"]
        mems = st.session_state.get("active_recalled_memories", [])

        st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)

        sev_class = "badge-critical" if inc["severity"] == "Critical" else "badge-high" if inc["severity"] == "High" else "badge-medium"
        conf_level = inv.get("root_cause_confidence", "Likely")
        conf_class = "badge-success" if conf_level == "Confirmed" else "badge-high" if conf_level == "Likely" else "badge-info"
        has_recalled_mem = len(mems) > 0 and mems[0].get("verified")

        st.markdown(f"""
        <div class="med-card" style="border-left: 4px solid {'#E5485D' if inc['severity'] == 'Critical' else '#E9A23B' if inc['severity'] == 'High' else '#087FA3'};">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 8px;">
                <div>
                    <span style="font-size: 0.72rem; color: #526777; font-weight: 700; text-transform: uppercase;">INVESTIGATION REPORT • {inc['incident_id']}</span>
                    <h2 style="margin: 4px 0; color: #172B3A; font-size: 1.25rem;">{inv.get('incident_summary', inc['error_message'])}</h2>
                </div>
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                    <span class="badge {sev_class}">{inc['severity']}</span>
                    <span class="badge {conf_class}">ROOT CAUSE: {conf_level.upper()}</span>
                    <span class="badge {'badge-success' if has_recalled_mem else 'badge-info'}">
                        {'🧠 MEMORY RECALLED' if has_recalled_mem else '⚡ NO PRIOR MEMORY'}
                    </span>
                    <span class="badge badge-medium">{inc['error_category']}</span>
                </div>
            </div>
            <div style="font-size: 0.76rem; color: #526777; margin-top: 6px;">
                Engine Source: <strong style="color:#172B3A;">{inv.get('analysis_source', 'RecallOps Engine')}</strong> • Memory Source: <strong style="color:#172B3A;">{mems[0].get('source_type') if mems else 'Local Persistent Cache'}</strong>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if inv.get("anti_pattern_warnings"):
            for warn in inv["anti_pattern_warnings"]:
                st.markdown(f"""
                <div style="background-color: #FEE2E2; border: 1px solid #FECACA; border-radius: 6px; padding: 12px; margin-bottom: 14px;">
                    <span class="badge badge-critical">ANTI-PATTERN WARNING</span>
                    <div style="font-size: 0.85rem; color: #991B1B; margin-top: 4px; font-weight: 700;">{warn}</div>
                </div>
                """, unsafe_allow_html=True)

        col_left, col_right = st.columns(2)
        with col_left:
            st.markdown("""
            <div class="med-card" style="height: 100%;">
                <h4 style="margin-top: 0; color: #087FA3; font-size: 1rem;">Detected Evidence</h4>
            """, unsafe_allow_html=True)
            for ev in inv.get("detected_evidence", []):
                st.markdown(f"• <code>{ev}</code>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with col_right:
            st.markdown(f"""
            <div class="med-card" style="height: 100%;">
                <h4 style="margin-top: 0; color: #E9A23B; font-size: 1rem;">Root Cause Analysis ({conf_level})</h4>
                <div style="font-size: 0.92rem; color: #172B3A; font-weight: 700; margin-bottom: 6px;">
                    {inv.get('possible_root_cause', 'Under investigation')}
                </div>
                <div style="font-size: 0.84rem; color: #263746; line-height: 1.5;">
                    {inv.get('explanation', '')}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)
        st.markdown("""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Hindsight Memory Experience Retrieval</h3>
        """, unsafe_allow_html=True)

        if mems:
            st.markdown(f"<p style='font-size:0.82rem; color:#7C3AED; font-weight:700;'>✓ Recalled {len(mems)} relevant experiences from Hindsight memory banks:</p>", unsafe_allow_html=True)
            for idx, m in enumerate(mems, 1):
                badge_type = "badge-critical" if m.get("is_anti_pattern") else "badge-success"
                st.markdown(f"""
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; border-left: 3px solid {'#E5485D' if m.get('is_anti_pattern') else '#087FA3'}; border-radius: 6px; padding: 12px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-size: 0.78rem; color: #087FA3; font-weight: 700;">PAST EXPERIENCE #{idx} • {m.get('incident_id', 'REF')} ({m.get('relevance', 'High')})</span>
                        <span class="badge {badge_type}">{m.get('outcome', 'Verified')}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #172B3A; font-weight:600; margin-bottom: 4px;"><strong>Context:</strong> {m.get('summary', '')}</div>
                    <div style="font-size: 0.82rem; color: #065F46; background: #E6F8F3; padding: 6px 10px; border-radius: 4px; font-family: 'JetBrains Mono', monospace;">
                        <strong>Applied Solution:</strong> {m.get('applied_solution', '')}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No prior verified memory exists for this specific signature. Resolve this incident and submit feedback to retain it into memory!")

        st.markdown("</div>", unsafe_allow_html=True)

        # Recommended Solutions
        st.markdown("""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Recommended Corrective Actions</h3>
        """, unsafe_allow_html=True)

        for sol in inv.get("recommended_solutions", []):
            if "PAST VERIFIED EXPERIENCE" in sol:
                st.markdown(f"""
                <div style="background: #E6F8F3; border: 1px solid #B8EBDD; border-radius: 6px; padding: 12px; margin-bottom: 8px;">
                    <span class="badge badge-success">RECOMMENDATION (FROM PAST VERIFIED EXPERIENCE)</span>
                    <div style="font-size: 0.92rem; color: #065F46; font-weight: 700; margin-top: 6px;">{sol}</div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"<div style='font-size: 0.86rem; color:#172B3A; margin-bottom: 4px;'>• {sol}</div>", unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

        # Inline Feedback & Learning Confirmation
        st.markdown(f"""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Resolve Incident {inc['incident_id']} & Store Verified Learning</h3>
            <p style="font-size: 0.82rem; color: #526777; margin-bottom: 12px;">Confirm your applied fix to retain it in Hindsight memory for future automated incident triage.</p>
        """, unsafe_allow_html=True)

        fb_type = st.selectbox(
            "Evaluation Outcome",
            ["Solution successful", "Alternative solution applied", "Partially successful", "Solution unsuccessful", "Still investigating"],
            key="inv_fb_type"
        )
        applied_fix_input = st.text_input("Applied Fix / Solution", placeholder="e.g. Increased maxPoolSize from 10 to 50 in HikariCP", key="inv_fix")
        comments_input = st.text_input("Developer Notes", placeholder="e.g. Load tested under 500 RPS; zero timeouts observed.", key="inv_comments")

        if st.button("Confirm Resolution & Retain in Memory Bank", type="primary"):
            updated = record_developer_feedback(
                incident_id=inc["incident_id"],
                feedback_type=fb_type,
                applied_solution=applied_fix_input,
                comments=comments_input
            )
            st.success(f"✓ Feedback retained! Incident {inc['incident_id']} updated to: {updated.get('resolution_status')}. Verified lessons stored in Hindsight.")

        st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# 4. ROOT CAUSE ANALYSIS PAGE
# =========================================================
elif nav_selection == "🔬 Root Cause Analysis":
    render_topbar(
        "Root Cause Analysis",
        "Deep-dive root cause investigation, evidence citation and solution formulation."
    )

    incidents = list_incidents(limit=50)
    if not incidents:
        st.info("No incidents currently in database to investigate. Ingest an incident in '🚀 New Investigation' first.")
    else:
        inc_options = [f"{r['incident_id']} | {r['error_category']} | {r['error_message'][:60]}..." for r in incidents]
        choice_idx = st.selectbox("Select Incident for Detailed Root Cause Investigation", range(len(inc_options)), format_func=lambda x: inc_options[x])
        active_inc = incidents[choice_idx]

        conf_level = active_inc.get("root_cause_confidence") or "Likely"
        conf_class = "badge-success" if conf_level == "Confirmed" else "badge-high" if conf_level == "Likely" else "badge-info"
        sev_class = "badge-critical" if active_inc["severity"] == "Critical" else "badge-high" if active_inc["severity"] == "High" else "badge-medium"

        st.markdown(f"""
        <div class="med-card" style="border-left: 4px solid {'#17A878' if conf_level == 'Confirmed' else '#E9A23B'};">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 1.05rem; font-weight: 700; color: #172B3A; font-family: 'JetBrains Mono', monospace;">{active_inc['incident_id']}</span>
                <div style="display: flex; gap: 6px;">
                    <span class="badge {sev_class}">{active_inc['severity']}</span>
                    <span class="badge {conf_class}">CONFIDENCE: {conf_level.upper()}</span>
                    <span class="badge badge-medium">{active_inc['error_category']}</span>
                </div>
            </div>
            <div style="font-size: 0.94rem; color: #172B3A; font-weight: 700;">{active_inc['error_message']}</div>
            <div style="font-size: 0.78rem; color: #526777; margin-top: 4px;">
                Component: <strong style="color:#172B3A;">{active_inc.get('component') or 'ApplicationCore'}</strong> • Status: <strong style="color:#172B3A;">{active_inc['resolution_status']}</strong> • Ingested: <strong style="color:#172B3A;">{active_inc['created_at']}</strong>
            </div>
        </div>
        """, unsafe_allow_html=True)

        rc1, rc2 = st.columns(2)
        with rc1:
            st.markdown(f"""
            <div class="med-card" style="height: 100%;">
                <h4 style="margin-top: 0; color: #087FA3; font-size: 1rem;">Root Cause Hypothesis</h4>
                <div style="font-size: 0.94rem; font-weight: 700; color: #172B3A; margin-bottom: 8px;">
                    {active_inc.get('possible_root_cause') or 'Pending technical determination'}
                </div>
                <div style="font-size: 0.85rem; color: #263746; line-height: 1.5;">
                    {active_inc.get('ai_explanation') or 'Log evidence points to downstream dependency starvation or network partition.'}
                </div>
            </div>
            """, unsafe_allow_html=True)

        with rc2:
            st.markdown("""
            <div class="med-card" style="height: 100%;">
                <h4 style="margin-top: 0; color: #E9A23B; font-size: 1rem;">Supporting Log Evidence</h4>
            """, unsafe_allow_html=True)
            ev_list = []
            try:
                ev_list = json.loads(active_inc.get("detected_evidence") or "[]")
            except Exception:
                ev_list = [active_inc.get("detected_evidence")] if active_inc.get("detected_evidence") else []

            if ev_list:
                for ev in ev_list:
                    st.markdown(f"• <code>{ev}</code>", unsafe_allow_html=True)
            else:
                st.markdown("• <code>Raw failure signature matched in application telemetry</code>", unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)

        st.markdown(f"""
        <div class="med-card">
            <h4 style="margin-top: 0; color: #17A878; font-size: 1rem;">Confirmed Resolution & Applied Fix</h4>
            <div style="font-size: 0.9rem; color: #065F46; font-family: 'JetBrains Mono', monospace; background: #E6F8F3; padding: 12px; border-radius: 6px; border: 1px solid #B8EBDD; margin-top: 6px;">
                {active_inc.get('applied_solution') or 'No solution verified yet. Provide feedback to confirm resolution.'}
            </div>
            {f"<div style='font-size: 0.8rem; color: #526777; margin-top: 8px;'>Developer Feedback: <strong style='color:#172B3A;'>{active_inc.get('developer_feedback')}</strong></div>" if active_inc.get('developer_feedback') else ""}
        </div>
        """, unsafe_allow_html=True)


# =========================================================
# 5. INCIDENT HISTORY PAGE
# =========================================================
elif nav_selection == "📜 Incident History":
    render_topbar(
        "Incident History",
        "Comprehensive audit trail of all analyzed incidents, resolution records, and applied fixes."
    )

    h_incidents = list_incidents(limit=100)
    st.caption(f"Displaying {len(h_incidents)} incident records from relational database storage")

    if h_incidents:
        h_df = pd.DataFrame(h_incidents)[["incident_id", "error_category", "severity", "resolution_status", "error_message", "applied_solution", "created_at"]]
        st.dataframe(h_df, use_container_width=True, hide_index=True)

        st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)
        st.markdown("""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Select Incident for Full Audit Record</h3>
        """, unsafe_allow_html=True)

        h_sel = st.selectbox("Choose Incident ID", [r["incident_id"] for r in h_incidents])
        h_rec = next(r for r in h_incidents if r["incident_id"] == h_sel)

        st.markdown(f"""
        <div style="background: #FFFFFF; border: 1px solid #DCE5ED; border-radius: 6px; padding: 14px; margin-top: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="font-size: 1.05rem; font-weight: 700; color: #087FA3; font-family: 'JetBrains Mono', monospace;">{h_rec['incident_id']}</span>
                <span class="badge badge-success">{h_rec['resolution_status']}</span>
            </div>
            <div style="font-size: 0.8rem; color: #526777; margin-bottom: 10px;">
                Category: <strong style="color:#172B3A;">{h_rec['error_category']}</strong> • Severity: <strong style="color:#172B3A;">{h_rec['severity']}</strong> • Created: <strong style="color:#172B3A;">{h_rec['created_at']}</strong>
            </div>
            <div style="margin-bottom: 8px;">
                <strong style="color: #172B3A; font-size:0.85rem;">Error Message:</strong><br>
                <code>{h_rec['error_message']}</code>
            </div>
            <div style="margin-bottom: 8px;">
                <strong style="color: #172B3A; font-size:0.85rem;">Suspected Root Cause:</strong><br>
                <span style="color: #263746; font-size:0.85rem;">{h_rec.get('possible_root_cause', 'N/A')}</span>
            </div>
            <div style="margin-bottom: 8px;">
                <strong style="color: #172B3A; font-size:0.85rem;">Confirmed Applied Solution:</strong><br>
                <span style="color: #065F46; font-family: 'JetBrains Mono', monospace; font-size:0.85rem;">{h_rec.get('applied_solution', 'Pending verification')}</span>
            </div>
            {f"<div><strong style='color: #172B3A; font-size:0.85rem;'>Developer Notes:</strong><br><span style='color: #263746; font-size:0.85rem;'>{h_rec.get('developer_feedback')}</span></div>" if h_rec.get('developer_feedback') else ""}
        </div>
        """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("No historical incidents recorded yet.")


# =========================================================
# 6. HINDSIGHT MEMORY PAGE
# =========================================================
elif nav_selection == "🧠 Hindsight Memory":
    render_topbar(
        "Hindsight Memory",
        "Recall previous experiences and improve future incident investigations."
    )

    mem_status = get_memory_status()
    cloud_ok = mem_status["cloud_status"]["connected"]

    # 4 Top Summary Cards via Grid
    st.markdown(f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px;">
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Memory Connection</span>
                <div class="summary-icon-box" style="background: {'#DCFCE7' if cloud_ok else '#E0F2FE'}; color: {'#17A878' if cloud_ok else '#078EBB'};">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                </div>
            </div>
            <div class="summary-value" style="font-size: 1.3rem;">{'Cloud Engine' if cloud_ok else 'Local Cache'}</div>
            <div class="summary-subtext">{'Synchronized' if cloud_ok else 'Persistent fallback'}</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Retained Experiences</span>
                <div class="summary-icon-box" style="background: #F3E8FF; color: #7C3AED;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                </div>
            </div>
            <div class="summary-value">{mem_status['local_cache_count']}</div>
            <div class="summary-subtext">Across 3 memory banks</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Successful Fixes</span>
                <div class="summary-icon-box" style="background: #DCFCE7; color: #17A878;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
            </div>
            <div class="summary-value">{mem_status['verified_solutions_count']}</div>
            <div class="summary-subtext">Verified developer fixes</div>
        </div>
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Anti-Patterns Tracked</span>
                <div class="summary-icon-box" style="background: #FEE2E2; color: #E5485D;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </div>
            </div>
            <div class="summary-value">{mem_status['anti_patterns_count']}</div>
            <div class="summary-subtext">Failed actions prevented</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    b1, b2, b3 = st.columns(3)
    with b1:
        st.markdown("""
        <div class="med-card">
            <span class="badge badge-medium">BANK #1 • HDFS</span>
            <h4 style="margin: 8px 0 4px 0; font-size: 0.95rem; color: #172B3A;">hdfs-intelligence</h4>
            <div style="font-size: 0.8rem; color: #263746;">2,000 cluster log events, failure templates, and replication timeouts.</div>
        </div>
        """, unsafe_allow_html=True)
    with b2:
        st.markdown("""
        <div class="med-card">
            <span class="badge badge-medium">BANK #2 • CODEBASE</span>
            <h4 style="margin: 8px 0 4px 0; font-size: 0.95rem; color: #172B3A;">swebench-intelligence</h4>
            <div style="font-size: 0.8rem; color: #263746;">300 verified software defect cases with production gold patches.</div>
        </div>
        """, unsafe_allow_html=True)
    with b3:
        st.markdown("""
        <div class="med-card">
            <span class="badge badge-success">BANK #3 • LIVE</span>
            <h4 style="margin: 8px 0 4px 0; font-size: 0.95rem; color: #172B3A;">incident-intelligence</h4>
            <div style="font-size: 0.8rem; color: #263746;">Developer-verified incident resolutions and anti-pattern warnings.</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="med-card">
        <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Search Memory Banks</h3>
        <p style="font-size: 0.82rem; color: #526777; margin-bottom: 10px;">Query semantically across all memory banks to retrieve relevant past experiences.</p>
    """, unsafe_allow_html=True)

    mem_q = st.text_input("Enter Query or Failure Signature", value="HikariPool connection timeout database pool exhausted")

    if mem_q.strip():
        recalled_memories = recall_incident_memories(mem_q, domain="incidents", top_k=5)
        st.markdown(f"<p style='font-size: 0.82rem; font-weight: 700; color: #087FA3;'>Found {len(recalled_memories)} matching memory items:</p>", unsafe_allow_html=True)
        for m in recalled_memories:
            badge_t = "badge-critical" if m.get("is_anti_pattern") else "badge-success"
            st.markdown(f"""
            <div style="background: #FFFFFF; border: 1px solid #DCE5ED; border-left: 3px solid {'#E5485D' if m.get('is_anti_pattern') else '#087FA3'}; border-radius: 6px; padding: 12px; margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="font-size: 0.78rem; color: #087FA3; font-weight: 700;">{m.get('incident_id', 'REF')} ({m.get('relevance', 'High')})</span>
                    <span class="badge {badge_t}">{m.get('outcome', 'Verified')}</span>
                </div>
                <div style="font-size: 0.88rem; color: #172B3A; font-weight: 700;">{m.get('summary', '')}</div>
                <div style="font-size: 0.82rem; color: #065F46; background: #E6F8F3; padding: 6px 10px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">
                    Applied Solution: {m.get('applied_solution', 'N/A')}
                </div>
                {f"<div style='font-size: 0.75rem; color: #526777; margin-top: 4px;'>Notes: <span style='color:#172B3A;'>{m.get('notes')}</span></div>" if m.get('notes') else ""}
            </div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# 7. SIMILAR EXPERIENCES (HDFS & SWE-BENCH)
# =========================================================
elif nav_selection == "💡 Similar Experiences":
    render_topbar(
        "Similar Experiences",
        "Explore past failure patterns and verified software patches from historical datasets."
    )

    t1, t2 = st.tabs(["HDFS Cluster Failure Telemetry", "SWE-bench Defect Intelligence"])

    with t1:
        st.markdown("""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">HDFS Cluster Anomaly Signatures</h3>
            <p style="font-size: 0.82rem; color: #526777;">2,000 log records analyzed for distributed file system failure patterns.</p>
        """, unsafe_allow_html=True)

        col_h1, col_h2, col_h3 = st.columns(3)
        col_h1.metric("Total Logs", f"{len(hdfs_df):,}")
        col_h2.metric("INFO Events", f"{(hdfs_df['Level'] == 'INFO').sum():,}")
        col_h3.metric("WARN Events", f"{(hdfs_df['Level'] == 'WARN').sum():,}")

        st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
        st.subheader("Top HDFS Event Templates")
        st.dataframe(hdfs_df["EventTemplate"].value_counts().head(8).reset_index(), use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with t2:
        st.markdown("""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">SWE-bench Software Defect Search</h3>
            <p style="font-size: 0.82rem; color: #526777;">Search 300 software issues to find verified gold patches and solutions.</p>
        """, unsafe_allow_html=True)

        swe_q = st.text_input("Search Codebase Issues", value="QuerySet empty filter causes AttributeError crash")
        if swe_q.strip():
            from sklearn.metrics.pairwise import cosine_similarity
            q_vec = swe_vectorizer.transform([swe_q])
            sims = cosine_similarity(q_vec, swe_tfidf_matrix).flatten()
            top_indices = sims.argsort()[-3:][::-1]

            st.markdown(f"<p style='font-size: 0.82rem; color: #087FA3; font-weight: 700;'>Top Matching Defect Cases:</p>", unsafe_allow_html=True)
            for idx in top_indices:
                row = swe_search_df.iloc[idx]
                sim_score = round(float(sims[idx]) * 100, 1)
                st.markdown(f"""
                <div style="background: #FFFFFF; border: 1px solid #DCE5ED; border-radius: 6px; padding: 12px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-size: 0.82rem; font-weight: 700; color: #087FA3;">{row['repo']} • {row['instance_id']}</span>
                        <span class="badge badge-medium">{sim_score}% MATCH</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #172B3A; font-weight:600; margin-bottom: 4px;">{str(row['issue_text'])[:160]}...</div>
                    <div style="font-size: 0.76rem; color: #065F46; background: #E6F8F3; padding: 4px 8px; border-radius: 4px; font-family: 'JetBrains Mono', monospace;">
                        Verified Patch Available (Difficulty: {row.get('difficulty') or 'Unspecified'})
                    </div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# 8. PREVENTION CENTER PAGE
# =========================================================
elif nav_selection == "🛡️ Prevention Center":
    render_topbar(
        "Prevention Center",
        "Identify recurring incidents and prevent repeated failures."
    )

    insights = generate_prevention_insights(hdfs_df=hdfs_df, swe_df=swe_df)

    p1, p2, p3 = st.columns(3)
    with p1:
        st.markdown(f"""
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Recurring Signatures</span>
                <div class="summary-icon-box" style="background: #FEE2E2; color: #E5485D;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
                </div>
            </div>
            <div class="summary-value">{len(insights['recurring_signatures'])}</div>
            <div class="summary-subtext">Frequency ≥ 2 detected</div>
        </div>
        """, unsafe_allow_html=True)

    with p2:
        st.markdown(f"""
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Active Guardrails</span>
                <div class="summary-icon-box" style="background: #E0F2FE; color: #078EBB;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                </div>
            </div>
            <div class="summary-value">{len(insights['prevention_runbooks'])}</div>
            <div class="summary-subtext">Automated prevention runbooks</div>
        </div>
        """, unsafe_allow_html=True)

    with p3:
        st.markdown(f"""
        <div class="summary-card">
            <div class="summary-header">
                <span class="summary-title">Verified Lessons</span>
                <div class="summary-icon-box" style="background: #DCFCE7; color: #17A878;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                </div>
            </div>
            <div class="summary-value">{insights['verified_solutions_count']}</div>
            <div class="summary-subtext">Retained in persistent memory</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)

    st.markdown("""
    <div class="med-card">
        <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Evidence-Based Recurring Incident Patterns</h3>
        <p style="font-size: 0.82rem; color: #526777; margin-bottom: 10px;">Dynamic recurrence matrix computed across live incidents and cluster telemetry.</p>
    """, unsafe_allow_html=True)

    if insights["recurring_signatures"]:
        st.dataframe(pd.DataFrame(insights["recurring_signatures"]), use_container_width=True, hide_index=True)
    else:
        st.info("No recurring patterns detected yet. Ingest multiple incidents to establish recurrence baselines.")

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("""
    <div class="med-card">
        <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Active Prevention Guardrails & Runbooks</h3>
    """, unsafe_allow_html=True)

    r_col1, r_col2 = st.columns(2)
    for idx, rb in enumerate(insights["prevention_runbooks"]):
        c_target = r_col1 if idx % 2 == 0 else r_col2
        with c_target:
            st.markdown(f"""
            <div style="background: #FFFFFF; border: 1px solid #DCE5ED; border-radius: 6px; padding: 14px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span class="badge badge-medium">{rb['id']}</span>
                    <span class="badge badge-high">{rb['risk_level']}</span>
                </div>
                <h4 style="margin: 4px 0; color: #172B3A; font-size: 0.95rem;">{rb['title']}</h4>
                <div style="font-size: 0.8rem; color: #D97706; margin-bottom: 6px;"><strong>Trigger:</strong> {rb['trigger_evidence']}</div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 8px 12px; border-radius: 4px; font-size: 0.82rem; color: #263746; line-height: 1.45; white-space: pre-line;">
                    {rb['recommendation']}
                </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# 9. ANALYTICS & REPORTS PAGE
# =========================================================
elif nav_selection == "📈 Analytics & Reports":
    render_topbar(
        "Analytics & Reports",
        "Comprehensive telemetry analytics, resolution performance and offline dataset benchmarks."
    )

    hdfs_eval = evaluate_hdfs_detection(hdfs_df)
    swe_eval = evaluate_swebench_retrieval(swe_df, swe_vectorizer, swe_tfidf_matrix)

    g1, g2 = st.columns(2)
    with g1:
        st.markdown("""
        <div class="med-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="margin: 0; font-size: 1rem; color: #172B3A;">Cluster Log Severity Ratio</h3>
                <span class="badge badge-info">HDFS Telemetry</span>
            </div>
        """, unsafe_allow_html=True)

        fig_s = px.pie(
            pd.DataFrame({"Severity": log_counts.index, "Count": log_counts.values}),
            names="Severity",
            values="Count",
            hole=0.6,
            color="Severity",
            color_discrete_map={"INFO": "#078EBB", "WARN": "#E9A23B"}
        )
        fig_s.update_layout(
            template="plotly_white",
            paper_bgcolor="#FFFFFF",
            plot_bgcolor="#FFFFFF",
            height=240,
            margin=dict(t=5, b=5, l=5, r=5),
            font=dict(family="Plus Jakarta Sans", color="#172B3A", size=12),
            legend=dict(font=dict(color="#172B3A", size=11))
        )
        st.plotly_chart(fig_s, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with g2:
        st.markdown("""
        <div class="med-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <h3 style="margin: 0; font-size: 1rem; color: #172B3A;">Defect Volume by Repository</h3>
                <span class="badge badge-medium">SWE-bench</span>
            </div>
        """, unsafe_allow_html=True)

        fig_r = px.bar(
            pd.DataFrame({"Repo": repo_counts.index[:6], "Issues": repo_counts.values[:6]}),
            x="Issues",
            y="Repo",
            orientation="h",
            color="Issues",
            color_continuous_scale=["#078EBB", "#13B8CF"]
        )
        fig_r.update_layout(
            template="plotly_white",
            paper_bgcolor="#FFFFFF",
            plot_bgcolor="#FFFFFF",
            height=240,
            margin=dict(t=5, b=5, l=5, r=5),
            font=dict(family="Plus Jakarta Sans", color="#172B3A", size=12),
            xaxis=dict(
                title=dict(text="", font=dict(color="#172B3A")),
                tickfont=dict(color="#263746", size=10),
                gridcolor="#DCE5ED"
            ),
            yaxis=dict(
                title=dict(text="", font=dict(color="#172B3A")),
                tickfont=dict(color="#263746", size=10),
                categoryorder="total ascending"
            ),
            coloraxis_showscale=False
        )
        st.plotly_chart(fig_r, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    g3, g4 = st.columns(2)
    with g3:
        st.markdown(f"""
        <div class="med-card">
            <span class="badge badge-info">OFFLINE DATASET BENCHMARK</span>
            <h3 style="margin: 6px 0 10px 0; font-size: 1rem; color: #172B3A;">HDFS Anomaly Detection Performance</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">ACCURACY</div>
                    <div style="font-size: 1.4rem; font-weight: 800; color: #17A878;">{hdfs_eval.get('accuracy_pct')}%</div>
                </div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">F1 SCORE</div>
                    <div style="font-size: 1.4rem; font-weight: 800; color: #078EBB;">{hdfs_eval.get('f1_score_pct')}%</div>
                </div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">PRECISION</div>
                    <div style="font-size: 1.3rem; font-weight: 800; color: #D97706;">{hdfs_eval.get('precision_pct')}%</div>
                </div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">RECALL</div>
                    <div style="font-size: 1.3rem; font-weight: 800; color: #7C3AED;">{hdfs_eval.get('recall_pct')}%</div>
                </div>
            </div>
            <div style="font-size: 0.78rem; color: #526777;">
                Evaluated against {hdfs_eval.get('sample_size'):,} labeled cluster log records.
            </div>
        </div>
        """, unsafe_allow_html=True)

    with g4:
        st.markdown(f"""
        <div class="med-card">
            <span class="badge badge-medium">OFFLINE DATASET BENCHMARK</span>
            <h3 style="margin: 6px 0 10px 0; font-size: 1rem; color: #172B3A;">SWE-bench Retrieval & Patches</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">PATCH AVAILABILITY</div>
                    <div style="font-size: 1.4rem; font-weight: 800; color: #17A878;">{swe_eval.get('patch_availability_rate')}%</div>
                </div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">AVG LATENCY</div>
                    <div style="font-size: 1.4rem; font-weight: 800; color: #078EBB;">{swe_eval.get('avg_retrieval_latency_ms')} ms</div>
                </div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">MEAN SIMILARITY</div>
                    <div style="font-size: 1.3rem; font-weight: 800; color: #D97706;">{swe_eval.get('mean_top1_similarity')}</div>
                </div>
                <div style="background: #F8FAFC; border: 1px solid #DCE5ED; padding: 10px; border-radius: 6px;">
                    <div style="font-size: 0.72rem; color: #263746; font-weight:700;">MAX SIMILARITY</div>
                    <div style="font-size: 1.3rem; font-weight: 800; color: #7C3AED;">{swe_eval.get('max_top1_similarity')}</div>
                </div>
            </div>
            <div style="font-size: 0.78rem; color: #526777;">
                Evaluated against {swe_eval.get('total_issues'):,} verified software issues across 12 production repositories.
            </div>
        </div>
        """, unsafe_allow_html=True)


# =========================================================
# 10. DEVELOPER FEEDBACK PAGE
# =========================================================
elif nav_selection == "💬 Developer Feedback":
    render_topbar(
        "Developer Feedback",
        "Human-in-the-loop feedback stored directly into Hindsight memory banks to refine future AI reflections."
    )

    fb_analytics = get_feedback_analytics()

    st.markdown(f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px;">
        <div class="summary-card">
            <div class="summary-header"><span class="summary-title">Resolution Success</span><div class="summary-icon-box" style="background:#DCFCE7;color:#17A878;"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"></polyline><polyline points="17 6 23 6 23 12"></polyline></svg></div></div>
            <div class="summary-value">{fb_analytics['resolution_success_rate']}%</div>
            <div class="summary-subtext">Verified resolutions</div>
        </div>
        <div class="summary-card">
            <div class="summary-header"><span class="summary-title">Acceptance Rate</span><div class="summary-icon-box" style="background:#E0F2FE;color:#078EBB;"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg></div></div>
            <div class="summary-value">{fb_analytics['acceptance_rate']}%</div>
            <div class="summary-subtext">Recommendations applied</div>
        </div>
        <div class="summary-card">
            <div class="summary-header"><span class="summary-title">Evaluated Incidents</span><div class="summary-icon-box" style="background:#F3E8FF;color:#7C3AED;"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg></div></div>
            <div class="summary-value">{fb_analytics['evaluated_resolutions_count']}</div>
            <div class="summary-subtext">Total verified reviews</div>
        </div>
        <div class="summary-card">
            <div class="summary-header"><span class="summary-title">Anti-Patterns</span><div class="summary-icon-box" style="background:#FEE2E2;color:#E5485D;"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></div></div>
            <div class="summary-value">{fb_analytics['unsuccessful_resolutions']}</div>
            <div class="summary-subtext">Unsuccessful attempts</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    incidents = list_incidents(limit=50)
    if not incidents:
        st.info("No incidents currently in the database to review. Ingest an incident in '🚀 New Investigation' first.")
    else:
        st.markdown("""
        <div class="med-card">
            <h3 style="margin-top: 0; font-size: 1rem; color: #172B3A;">Submit Developer Verification</h3>
        """, unsafe_allow_html=True)

        inc_options = [f"{r['incident_id']} | {r['error_category']} | {r['error_message'][:60]}..." for r in incidents]
        choice_idx = st.selectbox("Select Incident to Review", range(len(inc_options)), format_func=lambda x: inc_options[x])
        active_inc = incidents[choice_idx]

        st.markdown(f"""
        <div style="background: #FFFFFF; border: 1px solid #DCE5ED; border-radius: 6px; padding: 12px; margin: 10px 0;">
            <div style="font-size: 0.92rem; font-weight: 700; color: #087FA3;">{active_inc['incident_id']} ({active_inc['error_category']})</div>
            <div style="font-size: 0.85rem; color: #172B3A; font-weight:600; margin-top: 2px;">{active_inc['error_message']}</div>
            <div style="font-size: 0.78rem; color: #526777; margin-top: 4px;">Current Status: <strong style="color:#172B3A;">{active_inc['resolution_status']}</strong></div>
        </div>
        """, unsafe_allow_html=True)

        fb_type = st.radio(
            "Evaluation Outcome",
            [
                "Solution successful",
                "Alternative solution applied",
                "Partially successful",
                "Incorrect root cause",
                "Solution unsuccessful",
                "Still investigating"
            ],
            horizontal=True
        )

        applied_fix = st.text_input("Applied Fix / Solution", value=active_inc.get("applied_solution") or "")
        failure_reason = ""
        corrected_rc = ""
        corrected_sol = ""

        if fb_type == "Solution unsuccessful":
            failure_reason = st.text_input("Why did the proposed solution fail?", placeholder="e.g. Did not resolve timeout; thread contention persisted.")
        elif fb_type == "Incorrect root cause":
            corrected_rc = st.text_input("What was the actual root cause?", placeholder="e.g. Upstream API gateway rate limit rather than database pool")
            corrected_sol = st.text_input("What was the correct solution?", placeholder="e.g. Adjusted token bucket quota on API gateway")

        notes = st.text_area("Additional Developer Comments", placeholder="Document technical nuances for future team members...")

        if st.button("Submit Feedback to Hindsight Engine", type="primary"):
            updated = record_developer_feedback(
                incident_id=active_inc["incident_id"],
                feedback_type=fb_type,
                applied_solution=applied_fix,
                failure_reason=failure_reason,
                corrected_root_cause=corrected_rc,
                corrected_resolution=corrected_sol,
                comments=notes
            )
            st.success(f"✓ Feedback recorded! Incident {active_inc['incident_id']} updated to: {updated.get('resolution_status')}. Experience retained in Hindsight.")

        st.markdown("</div>", unsafe_allow_html=True)
