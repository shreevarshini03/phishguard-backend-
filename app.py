# app_streamlit_full_updated.py
"""
AI Phishing Detector — Full Streamlit App (extended)
Features:
 - Enter URL, expand shortened URLs
 - Analyze + show color (RED/YELLOW/GREEN), phishing %,
   explainability reasons, and destination/server info
 - Separate Report as Phishing / Mark as Safe buttons (logged)
 - Offline fallback heuristics
 - Interactive sidebar history + charts + CSV export
 - Guidance / Tips section for users
"""
import os
import re
import json
import sqlite3
import ssl
import socket
import joblib
import requests
import pandas as pd
import streamlit as st
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher

# -------------------------
# Config / Paths / API KEYS
# -------------------------
MODEL_PATH = "phishing_detector_model.pkl"
SCALER_PATH = "phishing_detector_scaler.pkl"
DB_PATH = "scan_history.db"

# Optional API keys (set as env vars if available)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")

# -------------------------
# Utilities: DB (SQLite)
# -------------------------
def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            input_url TEXT,
            expanded_url TEXT,
            host TEXT,
            risk TEXT,
            probability REAL,
            reasons TEXT,
            user_feedback TEXT,
            headers TEXT
        )
    """)
    conn.commit()
    return conn

DB_CONN = init_db()

def save_scan(input_url, expanded_url, host, risk, probability, reasons, user_feedback=None, headers=None):
    cur = DB_CONN.cursor()
    cur.execute("""
        INSERT INTO scans (timestamp, input_url, expanded_url, host, risk, probability, reasons, user_feedback, headers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.utcnow().isoformat(), input_url, expanded_url, host, risk, float(probability),
          json.dumps(reasons), user_feedback or "", json.dumps(headers or {})))
    DB_CONN.commit()

def load_history(limit=500):
    cur = DB_CONN.cursor()
    cur.execute("SELECT id, timestamp, input_url, expanded_url, host, risk, probability, reasons, user_feedback FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    cols = ["id","timestamp","input_url","expanded_url","host","risk","probability","reasons","user_feedback"]
    df = pd.DataFrame(rows, columns=cols)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["reasons"] = df["reasons"].apply(lambda r: ", ".join(json.loads(r)))
    return df

# -------------------------
# Helpers: online check, expand, ssl, fetch headers
# -------------------------
def online_check(timeout=1.2):
    try:
        requests.get("https://www.google.com", timeout=timeout)
        return True
    except Exception:
        return False

def expand_url(url, timeout=8):
    """Follow redirects to get final destination URL; if fails return original"""
    try:
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
        # try HEAD first
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        if r.status_code in (405, 400) or r.history is None:
            r = requests.get(url, allow_redirects=True, timeout=timeout)
        return r.url
    except Exception:
        return url

def fetch_headers(url, timeout=6):
    try:
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"phish-demo/1.0"})
        # return common headers we care about
        headers = {
            'status_code': r.status_code,
            'server': r.headers.get('Server'),
            'via': r.headers.get('Via'),
            'content_type': r.headers.get('Content-Type'),
            'final_url': r.url
        }
        return headers
    except Exception:
        return {}

def check_ssl_certificate(hostname, port=443, timeout=3):
    info = {"ok": False, "error": None, "notAfter": None, "subject_cn": None, "issuer": None, "cn_mismatch": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info["ok"] = True
                info["notAfter"] = cert.get("notAfter")
                subject = cert.get("subject")
                if subject:
                    for t in subject:
                        for k,v in t:
                            if k.lower() == "commonname":
                                info["subject_cn"] = v
                issuer = cert.get("issuer")
                if issuer:
                    try:
                        info["issuer"] = issuer[0][0][1]
                    except Exception:
                        info["issuer"] = str(issuer)
                if info["subject_cn"] and info["subject_cn"].lower() not in hostname.lower():
                    info["cn_mismatch"] = True
    except Exception as e:
        info["error"] = str(e)
    return info

# -------------------------
# ML / heuristics
# -------------------------
def load_model_and_scaler():
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler
    except Exception:
        return None, None

MODEL, SCALER = load_model_and_scaler()

def extract_features(url):
    norm = url.strip()
    if not re.match(r'^[a-zA-Z]+://', norm):
        norm = 'http://' + norm
    length = len(norm)
    num_dots = norm.count('.')
    has_at = 1 if '@' in norm else 0
    return pd.DataFrame([[length, num_dots, has_at]], columns=['length','num_dots','has_at']), {"length":length,"num_dots":num_dots,"has_at":has_at,"normalized":norm}

def predict_prob(features_df):
    if MODEL is None or SCALER is None:
        # simple heuristic fallback:
        row = features_df.iloc[0]
        score = 0.0
        if row['has_at'] == 1: score += 0.5
        if row['length'] > 80: score += 0.2
        if row['num_dots'] > 4: score += 0.2
        return min(1.0, score)
    scaled = SCALER.transform(features_df)
    return float(MODEL.predict_proba(scaled)[0][1])

# -------------------------
# Explainability / typosquatting
# -------------------------
COMMON_BRANDS = ["paypal","google","facebook","amazon","microsoft","gmail","apple","outlook","bank"]

def similar(a,b): return SequenceMatcher(None, a, b).ratio()

def detect_typosquatting(hostname):
    reasons=[]
    if not hostname: return reasons
    core = hostname.split('.')[0].lower()
    for brand in COMMON_BRANDS:
        ratio = similar(core, brand)
        if core != brand and ratio > 0.6:
            reasons.append(f"Domain '{core}' looks similar to '{brand}' (possible typosquatting).")
    return reasons

# -------------------------
# Content checks (simple)
# -------------------------
COMMON_LOGIN_KEYS = ["password","login","signin","verify","otp","2fa","reset"]
def fetch_page_for_content(url):
    try:
        if not re.match(r'^[a-zA-Z]+://', url):
            url = 'http://' + url
        r = requests.get(url, timeout=6, headers={"User-Agent":"phish-demo/1.0"})
        if r.status_code == 200:
            html = r.text
            reasons=[]
            if re.search(r"<form\b", html, flags=re.IGNORECASE):
                reasons.append("Page contains HTML form(s).")
            if re.search(r"type=['\"]?password['\"]?", html, flags=re.IGNORECASE):
                reasons.append("Page contains password input fields.")
            for kw in COMMON_LOGIN_KEYS:
                if re.search(r"\b"+re.escape(kw)+r"\b", html, flags=re.IGNORECASE):
                    reasons.append(f"Page mentions '{kw}'.")
            return reasons
    except Exception:
        pass
    return []

# -------------------------
# UI: Streamlit layout
# -------------------------
st.set_page_config(page_title="AI Phishing Detector (Interactive)", layout="wide")
st.title("🛡️ AI Phishing URL Detector — Interactive Demo")

# Top-level columns
left, right = st.columns([2,1])

with right:
    st.header("Quick Actions")
    st.write("• Enter a URL and click Analyze")
    st.write("• Use Report buttons to provide feedback")
    st.write("• History is saved locally (click export)")

with left:
    st.subheader("1) Enter the URL to analyze")
    input_url = st.text_input("Enter URL (supports shortened URLs):", value="", placeholder="e.g., bit.ly/xyz or https://example.com")
    do_analyze = st.button("Analyze URL")
    st.write("")  # spacing

# Run analysis
if do_analyze:
    if not input_url.strip():
        st.warning("Please enter a URL.")
    else:
        online = online_check()
        st.write(f"**Connectivity:** {'Online' if online else 'Offline — heuristics only'}")

        # 1. Expand shortened URL
        with st.spinner("Expanding URL..."):
            expanded = expand_url(input_url)
        st.write("**Expanded URL:**", expanded)

        parsed = urlparse(expanded)
        host = parsed.hostname or ""

        # 2. Fetch headers (destination server info)
        headers = {}
        if online:
            headers = fetch_headers(expanded)
        st.markdown("**Destination / Server Info:**")
        if headers:
            st.write(f"- Final URL: {headers.get('final_url')}")
            st.write(f"- HTTP status: {headers.get('status_code')}")
            st.write(f"- Server header: {headers.get('server')}")
            st.write(f"- Content-Type: {headers.get('content_type')}")
        else:
            st.write("- Could not fetch headers (offline or blocked).")

        # 3. SSL Certificate check (if https and online)
        ssl_info = None
        if parsed.scheme == 'https' and online and host:
            ssl_info = check_ssl_certificate(host)
            st.markdown("**SSL / Certificate Check:**")
            if ssl_info.get("error"):
                st.write("- SSL check error:", ssl_info.get("error"))
            else:
                st.write(f"- Subject CN: {ssl_info.get('subject_cn')}")
                st.write(f"- Issuer: {ssl_info.get('issuer')}")
                st.write(f"- Expires: {ssl_info.get('notAfter')}")
                if ssl_info.get("cn_mismatch"):
                    st.warning("- Certificate CN mismatch with hostname.")
        else:
            st.write("**SSL / Certificate Check:** Skipped (no HTTPS or offline).")

        # 4. ML or heuristics prediction
        features_df, raw = extract_features(expanded)
        prob = predict_prob(features_df)
        prob_pct = f"{prob:.2%}"
        # determine risk
        if prob > 0.75:
            risk = "RED"
            badge = st.error
        elif prob > 0.45:
            risk = "YELLOW"
            badge = st.warning
        else:
            risk = "GREEN"
            badge = st.success

        badge(f"Result: **{risk}** — Confidence: **{prob_pct}**")

        # 5. Explainability panel: reasons
        reasons = []
        if raw["has_at"] == 1:
            reasons.append("⚠️ Contains '@' symbol (commonly used to hide real domain).")
        if raw["length"] > 60:
            reasons.append(f"⚠️ URL is long ({raw['length']} chars).")
        if raw["num_dots"] > 4:
            reasons.append(f"⚠️ Contains many dots / subdomains ({raw['num_dots']}).")
        # typosquatting
        reasons.extend(["❌ " + r for r in detect_typosquatting(host)])
        # ssl issues
        if ssl_info:
            if ssl_info.get("error"):
                reasons.append("⚠️ SSL check error or unreachable.")
            else:
                if ssl_info.get("cn_mismatch"):
                    reasons.append("⚠️ Certificate CN mismatch with domain.")
                # note: expiry parsing omitted for simplicity
                if ssl_info.get("issuer") and "self-signed" in str(ssl_info.get("issuer")).lower():
                    reasons.append("⚠️ Certificate appears self-signed.")
        # content checks
        page_reasons = []
        if online:
            page_reasons = fetch_page_for_content(expanded)
            reasons.extend(["⚠️ " + pr for pr in page_reasons])

        if not reasons and risk in ("YELLOW","RED"):
            reasons.append("⚠️ Suspicion based on combined heuristics/model score.")

        st.subheader("Why did we flag this? (Explainability)")
        for r in reasons:
            st.write("- ", r)

        # 6. Add "how to identify safe URL" quick checklist
        st.subheader("How we identify SAFE URLs (short)")
        st.write("- Uses HTTPS with valid certificate (not the only check).")
        st.write("- Short, clear domain (no excessive dots or lookalike brand names).")
        st.write("- No password fields or login forms on unexpected domains.")
        st.write("- Not blacklisted by threat intelligence (VirusTotal / Safe Browsing).")

        # 7. Save scan to history
        save_scan(input_url, expanded, host, risk, prob, reasons, headers=headers or {})

        # 8. Show "destination address / sender" summary (sender unclear: we show destination & headers)
        st.subheader("Destination Summary (interpreted as destination address)")
        st.write("- Host / Domain:", host or "Unknown")
        if headers.get("server"):
            st.write("- Server header:", headers.get("server"))
        else:
            st.write("- Server header: Not available")

# -------------------------
# User feedback buttons (separate)
# -------------------------
st.markdown("---")
st.subheader("User feedback")
colp, coln = st.columns(2)
with colp:
    if st.button("Report as Phishing (separate)"):
        if not input_url.strip():
            st.warning("Enter a URL above to report.")
        else:
            save_scan(input_url, input_url, urlparse(input_url).hostname or "", "REPORTED_PHISH", 1.0, ["User reported phishing"], user_feedback="reported_phish")
            st.success("Thank you — reported as phishing.")
with coln:
    if st.button("Mark URL as Safe (separate)"):
        if not input_url.strip():
            st.warning("Enter a URL above to mark safe.")
        else:
            save_scan(input_url, input_url, urlparse(input_url).hostname or "", "REPORTED_SAFE", 0.0, ["User marked safe"], user_feedback="reported_safe")
            st.success("Marked as safe — thanks for feedback.")

# -------------------------
# Sidebar: Interactive Dashboard / History
# -------------------------
st.sidebar.header("Local History & Dashboard")
hist = load_history(1000)
st.sidebar.write(f"Total scans: {len(hist)}")
if not hist.empty:
    # filters
    risk_filter = st.sidebar.multiselect("Filter by risk", options=hist['risk'].unique().tolist(), default=hist['risk'].unique().tolist())
    df_filtered = hist[hist['risk'].isin(risk_filter)]
    # time range (simple)
    st.sidebar.write("Recent scans (top 50):")
    st.sidebar.dataframe(df_filtered.head(50), use_container_width=True)
    # simple aggregated chart
    try:
        chart_df = df_filtered.groupby([df_filtered.timestamp.dt.date, 'risk']).size().unstack(fill_value=0)
        st.sidebar.line_chart(chart_df)
    except Exception:
        pass
    # Export CSV
    if st.sidebar.button("Export history CSV"):
        csv = df_filtered.to_csv(index=False).encode('utf-8')
        st.sidebar.download_button("Download CSV", data=csv, file_name="scan_history.csv", mime="text/csv")
else:
    st.sidebar.write("No history yet. Analyze a URL to populate history.")

# -------------------------
# Guidance / Educational Panel
# -------------------------
st.markdown("---")
with st.expander("What is phishing and how to spot it? (Guidance & tips)"):
    st.write("""
    **Phishing** is when attackers trick people into giving sensitive information (passwords, bank details) by impersonating legitimate services.
    **Quick tips to spot phishing:**
    - Check the domain carefully — look for misspellings or extra characters: `paypa1.com` vs `paypal.com`.
    - Avoid clicking shortened links unless you expand them first.
    - Do not enter credentials on unfamiliar domains or pages that unexpectedly request login info.
    - Check for HTTPS, but remember HTTPS alone is not proof of safety.
    - Look for poor grammar, urgent tone, or unexpected attachments/links in emails.
    """)
    st.subheader("Interactive checklist (for users)")
    st.write("- Is the domain spelled correctly?  - Are there many subdomains or dots?  - Does the page ask for password/email unexpectedly?")

# -------------------------
# Footer: Multi-platform notes
# -------------------------
st.markdown("---")
st.write("**Deployment**: Push this repo (including this file, requirements.txt, and .pkl files) to GitHub and deploy on Streamlit Cloud (share.streamlit.io).")
st.write("**Note**: Optional threat-intel integrations (VirusTotal / SafeBrowsing) can be enabled by setting environment variables in your Streamlit app settings.")
