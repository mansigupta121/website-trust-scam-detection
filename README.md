#  Website Trust & Scam Detection

A Python-based cybersecurity tool that analyzes websites to determine whether they are **legitimate or potentially fraudulent** using OSINT, network scanning, and heuristic risk scoring.

---

##  Features
-  Website fingerprinting using **WhatWeb**
-  Port scanning & service detection using **Nmap**
-  Directory enumeration using **Gobuster**
-  Vulnerability detection using **Nikto**
-  HTTPS & SSL certificate validation
-  Risk scoring system (0–100) based on multiple security indicators
-  Scam detection using:
  - Domain age analysis
  - Security headers check
  - Sensitive file exposure detection
  - Email classification (free vs domain)
  - Legal pages & company info verification
  - Soft-404 / CDN behavior detection

---

##  Tech Stack
- Python
- Nmap
- Gobuster / Dirb
- WhatWeb
- Nikto
- OSINT Techniques

---

##  How to Run
```bash
# Install dependencies
pip install requests python-whois python-nmap

# Run the script
python3 detection.py
```

Enter the website URL when prompted.

---

##  Output
- Website security analysis report
- Detected vulnerabilities and exposures
- Final **Trust Score (0–100)**
- Risk classification:
  - Low Risk
  - Medium Risk
  - High Risk

---

##  Future Improvements
- GST verification (India-specific business validation)
- Machine learning-based scam detection
- Web UI dashboard

---

##  License
For educational and research purposes only.
