from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re
from bs4 import BeautifulSoup
from googleapiclient import discovery
import sqlite3
from collections import Counter
import os
import random

# Pydantic models for requests/responses
class ScanRequest(BaseModel):
    url: str

class ReportRequest(BaseModel):
    url: str
    verdict: str  # "phish" or "safe"

# App setup
app = FastAPI(title="PhishGuard API", description="Phishing Detection Tool")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Databases
conn_scans = sqlite3.connect('scans.db', check_same_thread=False)
conn_scans.execute('CREATE TABLE IF NOT EXISTS scans (url TEXT, result TEXT, timestamp TEXT)')
conn_reports = sqlite3.connect('reports.db', check_same_thread=False)
conn_reports.execute('CREATE TABLE IF NOT EXISTS reports (url TEXT, verdict TEXT, timestamp TEXT)')

# Tips for gamification
TIPS = [
    "Phishers often use lookalike domains like 'paypall.com'. Always check the URL carefully.",
    "Be cautious of links with too many subdomains, e.g., secure.login.example.com.",
    "Never enter credentials on non-official sites—verify the domain matches the brand."
]

# 1. URL Shortener Expander
def expand_shortened_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        return response.url
    except Exception:
        return url

# 2. SSL/Certificate Trust Check
def check_ssl(url):
    hostname = url.split('://')[1].split('/')[0].replace('www.', '')
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                
                # Expiry
                expiry = datetime.fromtimestamp(x509_cert.not_valid_after.timestamp())
                expired = expiry < datetime.now()
                
                # Self-signed (simplified)
                self_signed = x509_cert.issuer.rfc4514_string() == x509_cert.subject.rfc4514_string()
                
                # CN mismatch
                cn = next((attr.value for attr in x509_cert.subject if attr.oid._name == 'commonName'), '')
                cn_mismatch = hostname not in cn.lower()
                
                warnings = []
                if expired: warnings.append("Expired SSL")
                if self_signed: warnings.append("Self-signed cert")
                if cn_mismatch: warnings.append("Domain mismatch")
                
                return "Safe" if not warnings else f"Suspicious: {'; '.join(warnings)}"
    except Exception:
        return "Unable to check SSL (connection failed)"

# 3 & 8. Heuristics for Offline/Explainability
def run_heuristics(url):
    checks = {
        "domain_valid": True,  # Placeholder; use tldextract for real
        "contains_at": "@" in url,
        "long_url": len(url) > 100,
        "typo_squatting": any(s in url.lower() for s in ["paypa1", "g00gle", "arnazon"])  # Simple examples
    }
    return checks

# 4. Threat Intelligence (Google Safe Browsing)
def check_safe_browsing(url):
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return True  # Fallback to safe if no key
    
    try:
        service = discovery.build('safebrowsing', 'v4', developerKey=api_key)
        body = {
            'client': {'clientId': 'phishguard', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        response = service.threatMatches().find(body=body).execute()
        return len(response.get('matches', [])) == 0  # Safe if no matches
    except Exception:
        return True  # Fallback

# 6. Suspicious Page Content Check
def check_page_content(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        text = soup.get_text().lower()
        forms = soup.find_all('form')
        suspicious_keywords = re.search(r'password|login|reset|username|credit card', text)
        suspicious = bool(suspicious_keywords) and len(forms) > 0
        return "Suspicious content (login form detected)" if suspicious else "Clean"
    except Exception:
        return "Unable to fetch page"

# Offline detection
def is_online():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except:
        return False

# Main scan logic
@app.post("/scan")
def scan_url(request: ScanRequest):
    url = request.url
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Expand shortened URL
    expanded_url = expand_shortened_url(url)
    
    # Offline fallback
    offline = not is_online()
    checks = {}
    
    if offline:
        checks = run_heuristics(expanded_url)
        content_result = "Offline: Skipping content check"
        ssl_result = "Offline: Skipping SSL check"
        safe_browsing = True
    else:
        # Full checks
        checks = run_heuristics(expanded_url)
        ssl_result = check_ssl(expanded_url)
        content_result = check_page_content(expanded_url)
        safe_browsing = check_safe_browsing(expanded_url)
        if "Suspicious" in ssl_result: checks["ssl_suspicious"] = True
        if "Suspicious" in content_result: checks["content_suspicious"] = True
        checks["blacklisted"] = not safe_browsing
    
    # Scoring: Count issues (True = issue)
    issues = sum(checks.values())
    color = "Green" if issues == 0 else "Yellow" if issues <= 2 else "Red"
    
    # Save to DB
    conn_scans.execute('INSERT INTO scans VALUES (?, ?, ?)', (expanded_url, color, datetime.now().isoformat()))
    conn_scans.commit()
    
    # Response with explainability and tip
    tip = random.choice(TIPS)
    return {
        "color": color,
        "expanded_url": expanded_url,
        "offline_mode": offline,
        "checks": checks,  # For explainability panel (e.g., {"contains_at": false} → ✅ if not issue)
        "detailed": {
            "ssl": ssl_result,
            "content": content_result,
            "safe_browsing": "Clear" if safe_browsing else "Blacklisted!"
        },
        "tip": tip
    }

# 5. User Reporting
@app.post("/report")
def report_url(request: ReportRequest):
    conn_reports.execute('INSERT INTO reports VALUES (?, ?, ?)', (request.url, request.verdict, datetime.now().isoformat()))
    conn_reports.commit()
    return {"status": "Reported successfully", "message": f"URL {request.url} marked as {request.verdict}"}

# 7. History Dashboard (aggregation)
@app.get("/history")
def get_history():
    cursor = conn_scans.execute('SELECT result FROM scans')
    results = [row[0] for row in cursor.fetchall()]
    counts = Counter(results)
    total = len(results)
    return {
        "summary": {
            "red": counts.get("Red", 0),
            "yellow": counts.get("Yellow", 0),
            "green": counts.get("Green", 0),
            "total_scans": total
        },
        "recent_scans": conn_scans.execute('SELECT url, result, timestamp FROM scans ORDER BY timestamp DESC LIMIT 10').fetchall()
    }

# 9. Gamification endpoint (optional, for tips only)
@app.get("/tips")
def get_tip():
    return {"tip": random.choice(TIPS)}

# Health check
@app.get("/")
def root():
    return {"message": "PhishGuard API is running! Use /docs for endpoints."}

# 10. Multi-platform: This API works for web/extension/PWA
