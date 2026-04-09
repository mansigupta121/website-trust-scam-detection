#!/usr/bin/env python3
import requests
import subprocess
import whois
import socket
from datetime import datetime
import os
import re
import json
import random
import string
import difflib
import time
from urllib.parse import urlparse

# ---------------- CONFIG -------------------

GOBUSTER_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
GOBUSTER_THREADS = "30"

SOCKET_TIMEOUT = 6
SUBPROCESS_TIMEOUT = 120  # seconds
SOFT_404_TRIES = 5
SOFT_404_SIM_THRESH = 0.90
CDN_SIM_THRESH = 0.92
FREE_EMAIL_DOMAINS = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me", "yandex.com", "live.com"}

LEGAL_PAGES = [
    "/about", "/about-us", "/contact", "/contact-us", "/privacy",
    "/privacy-policy", "/terms", "/terms-and-conditions",
    "/refund", "/return-policy", "/shipping", "/shipping-policy"
]

SENSITIVE_FILES = [
    ".env", ".htpasswd", ".htaccess", ".mysql_history",
    ".rhosts", ".bashrc", ".bash_history", ".forward",
    "config.php", "wp-config.php", "env", "environ"
]

# ---------------- HELPERS -------------------

def fetch_url(url, timeout=8, allow_redirects=True):
    r = requests.get(url, timeout=timeout, allow_redirects=allow_redirects)
    return r.status_code, r.text, {k.lower(): v for k, v in r.headers.items()}

# ---------------- SOFT-404 + CDN DETECTOR -------------------

def detect_soft_404_and_cdn(url: str, homepage_text: str) -> dict:
    results = {
        "tries": 0,
        "sizes": [],
        "homepage_sim": [],
        "between_sim": [],
        "matches_homepage": 0,
        "cdn_fallback": False,
        "soft_404": False,
    }

    random_texts = []

    for _ in range(SOFT_404_TRIES):
        rp = "/" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        test_url = url.rstrip("/") + rp

        try:
            sc, text, headers = fetch_url(test_url)
        except:
            continue

        results["tries"] += 1
        random_texts.append(text)
        results["sizes"].append(len(text))

        # Compare to homepage
        ratio = difflib.SequenceMatcher(None, homepage_text, text).quick_ratio()
        results["homepage_sim"].append(ratio)
        if ratio > SOFT_404_SIM_THRESH:
            results["matches_homepage"] += 1

        time.sleep(0.2)

    # Compare random fallback pages to each other
    if len(random_texts) > 1:
        base = random_texts[0]
        identical = 0

        for txt in random_texts[1:]:
            r = difflib.SequenceMatcher(None, base, txt).quick_ratio()
            results["between_sim"].append(r)
            if r > CDN_SIM_THRESH:
                identical += 1

        if identical >= len(random_texts) - 2:
            results["cdn_fallback"] = True

    # CDN fallback always implies soft-404 behavior
    results["soft_404"] = results["cdn_fallback"]
    return results

# ---------------- EMAIL EXTRACTION -------------------

EMAIL_RE = re.compile(r"[a-zA-Z0-9.\-+_]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

def extract_emails(html: str) -> list:
    if not html:
        return []
    found = set(m.group(0).replace("mailto:", "").replace(",", "") for m in EMAIL_RE.finditer(html))
    return sorted(found)

def classify_emails(emails: list) -> dict:
    free, domain = [], []
    for e in emails:
        try:
            local, dom = e.split("@")
        except:
            continue
        if dom.lower() in FREE_EMAIL_DOMAINS:
            free.append(e)
        else:
            domain.append(e)
    return {"all": emails, "free": free, "domain": domain, "has_free": bool(free)}

# ---------------- PLATFORM DETECTION -------------------

def detect_platforms(whatweb_output: str) -> list:
    ww = whatweb_output.lower()
    platforms = []
    if "shopify" in ww or "myshopify" in ww:
        platforms.append("shopify")
    if "cloudflare" in ww:
        platforms.append("cloudflare")
    if "woocommerce" in ww:
        platforms.append("woocommerce")
    return platforms

# ---------------- LEGAL PAGES -------------------

def check_paths_exist(base_url: str, paths: list, homepage_text: str, soft_info: dict) -> dict:
    results = {}
    soft = soft_info.get("soft_404", False)

    for p in paths:
        full = base_url.rstrip("/") + p
        try:
            sc, text, headers = fetch_url(full)
        except:
            results[p] = {"present": False}
            continue

        if soft:
            # Only consider the page present if DIFFERENT from fallback
            ratio = difflib.SequenceMatcher(None, homepage_text, text).quick_ratio()
            results[p] = {"present": ratio < 0.80}
        else:
            results[p] = {"present": sc in (200, 301, 302)}

        time.sleep(0.15)

    return results

# ---------------- COMPANY INFO -------------------

def find_company_info(html: str) -> dict:
    s = html.lower() if html else ""
    return {
        "phone": bool(re.search(r"\b\d{10}\b", s)),
        "address": bool(re.search(r"\b(address|street|road|city|zip|postal|pin)\b", s)),
        "company_name": bool(re.search(r"\b(inc|llc|ltd|pvt|private|limited|company|corporation)\b", s)),
        "gst_cin": bool(re.search(r"\b(gst|cin|vat|tax)\b", s)),
    }

# ---------------- WHATWEB / NMAP / GOBUSTER -------------------

def run_whatweb(url):
    try:
        print("\n[+] Running WhatWeb…")
        out = subprocess.check_output(["whatweb", url], stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT)
        return out.decode(errors="ignore")
    except Exception as e:
        return f"WhatWeb error: {e}"

def run_nmap(url, top_ports=200):
    try:
        host = urlparse(url).hostname
        cmd = ["nmap", "-sV", "-Pn", "--top-ports", str(top_ports), host]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT + 30)
        return out.decode(errors="ignore")
    except:
        return "nmap error"

def run_gobuster(url):
    try:
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", GOBUSTER_WORDLIST,
            "-t", GOBUSTER_THREADS,
            "-q"
        ]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=SUBPROCESS_TIMEOUT)
        return out.decode(errors="ignore")
    except:
        return "gobuster error"

# ---------------- GOBUSTER ANALYSIS (Caution Mode) -------------------

def analyze_gobuster_output(gob_out, homepage_text, soft_info, platforms):
    res = {
        "hits": [],
        "sensitive_hits": [],
        "false_positive": False,
        "reason": ""
    }

    if "error" in gob_out or not gob_out.strip():
        return res

    for line in gob_out.splitlines():
        m = re.match(r"(/[\S]*)\s+\(Status:\s*(\d+)\)", line)
        if m:
            res["hits"].append({"path": m.group(1), "status": int(m.group(2)), "raw": line})

    # CDN fallback check
    if soft_info.get("cdn_fallback"):
        res["false_positive"] = True
        res["reason"] = "CDN fallback detected — all invalid paths return the same content"
        return res

    # Shopify fallback check
    if "shopify" in platforms:
        res["false_positive"] = True
        res["reason"] = "Shopify store detected — Gobuster results unreliable"
        return res

    # Real server: extract sensitive hits
    for h in res["hits"]:
        low = h["path"].lower()
        for s in SENSITIVE_FILES:
            if s in low:
                res["sensitive_hits"].append(h)

    return res

# ---------------- BASIC CHECKS -------------------

def check_https(url):
    return url.startswith("https://")

def check_ssl_certificate(url):
    try:
        import ssl
        hostname = urlparse(url).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
        return True
    except:
        return False

def check_domain_age(url):
    try:
        domain = urlparse(url).hostname
        w = whois.whois(domain)
        c = w.creation_date
        if isinstance(c, list):
            c = c[0]
        return (datetime.now() - c).days
    except:
        return "unknown"

# ---------------- MAIN -------------------

def main():
    print("\n===  E-COMMERCE SCAM DETECTOR  ===\n")

    url = input("Enter website URL (with http/https): ").strip()
    print()

    # Fetch homepage
    try:
        hp_status, hp_text, hp_headers = fetch_url(url)
        print(f"[+] Homepage fetched: status {hp_status}, length {len(hp_text)} bytes")
    except Exception as e:
        print("[-] Could not fetch homepage:", e)
        return

    # 1. HTTPS
    print("\n1) HTTPS Check:")
    print(" Uses HTTPS" if check_https(url) else " Does NOT use HTTPS (risky!)")

    # 2. SSL
    print("\n2) SSL Certificate:")
    print(" SSL VALID" if check_ssl_certificate(url) else " SSL INVALID or missing")

    # 3. Domain Age
    age = check_domain_age(url)
    print("\n3) Domain Age:", age, "days")

    # 4. WhatWeb
    print("\n4) WhatWeb Fingerprint:")
    ww = run_whatweb(url)
    print(ww)

    # Detect platforms
    platforms = detect_platforms(ww)
    print("\n[+] Detected Platforms:", platforms)

    # 5. Soft-404 + CDN
    print("\n5) Soft-404 / CDN Inspection:")
    soft = detect_soft_404_and_cdn(url, hp_text)
    print(json.dumps(soft, indent=2))

    # 6. Nmap
    print("\n6) Nmap Scan:")
    nmap_out = run_nmap(url)
    print(nmap_out[:500])

    # 7. Gobuster
    print("\n7) Gobuster Scan:")
    gob_out = run_gobuster(url)
    print(gob_out[:400])

    gob_analysis = analyze_gobuster_output(gob_out, hp_text, soft, platforms)
    print("\n[+] Gobuster Analysis:")
    print(json.dumps(gob_analysis, indent=2))

    # 8. Security headers
    print("\n8) Security Headers:")
    for k, v in hp_headers.items():
        print(f"{k}: {v}")

    # 9. Email checks
    emails = extract_emails(hp_text)
    email_info = classify_emails(emails)
    print("\n9) Emails found:")
    print(json.dumps(email_info, indent=2))

    # 10. Legal pages
    print("\n10) Legal / Contact Pages:")
    pages = check_paths_exist(url, LEGAL_PAGES, hp_text, soft)
    present = [p for p, info in pages.items() if info["present"]]
    print("Present:", present)

    # 11. Company info
    company = find_company_info(hp_text)
    print("\n11) Company Info Heuristics:")
    print(company)

    # 12. E-commerce signals
    s = hp_text.lower()
    ecom_signals = {
        "product_schema": ("\"@type\":\"product\"" in s),
        "cart": ("add to cart" in s),
        "checkout": ("checkout" in s),
        "payment": [p for p, m in {
            "stripe": ["stripe.js", "checkout.stripe.com"],
            "razorpay": ["razorpay"],
            "paypal": ["paypal.com"]
        }.items() if any(x in s for x in m)],
        "platforms": platforms
    }
    print("\n12) E-commerce Signals:")
    print(json.dumps(ecom_signals, indent=2))

    # ---------------- RISK SCORE -------------------
    print("\n=== FINAL RISK SCORE ===")

    risk = 0

    if not check_https(url): risk += 20
    if not check_ssl_certificate(url): risk += 20
    if isinstance(age, int) and age < 60: risk += 10

    # suspicious ports
    risky_ports = ["3389/", "5432/", "3306/"]
    if any(p in nmap_out for p in risky_ports):
        risk += 20

    # Gobuster scoring (Caution mode)
    if gob_analysis["false_positive"]:
        print("\n[!] Gobuster results flagged as FALSE POSITIVES due to:", gob_analysis["reason"])
    else:
        if gob_analysis["sensitive_hits"]:
            risk += 50

    # missing security headers
    required = ["content-security-policy", "x-frame-options", "strict-transport-security"]
    missing_headers = sum(1 for h in required if h not in hp_headers)
    risk += min(missing_headers * 4, 12)

    # free email domain
    if email_info["has_free"]:
        risk += 10

    # missing legal pages
    if len(present) < 3:
        risk += 10

    # missing company info
    if not any(company.values()):
        risk += 10

    # missing ecommerce signs
    if not any(ecom_signals.values()):
        risk += 10

    risk = min(risk, 100)
    print(f"RISK = {risk}/100")

    if risk > 75:
        print(" HIGH RISK — Potential Scam / Unsafe")
    elif risk > 40:
        print(" MEDIUM RISK — Investigate Further")
    else:
        print(" LOW RISK — Likely Safe")

    print("\n--- SCAN COMPLETE ---")

if __name__ == "__main__":
    main()
