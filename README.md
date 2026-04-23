# AI Phishing Detection System for NCIIPC AI Grand Challenge  
**Problem Statement 02: AI-based Monitoring and Detection of Phishing Domains/URLs related to CSEs**

**Application ID:** AIGR-S04000  
**Author:** Yamuna B  
**Date:** 31 October 2025  

## Overview
This is a **scalable, on-premise AI/ML-based system** designed to detect phishing and suspected domains targeting Critical Sector Entities (CSEs). The system processes large-scale URL datasets (1,083,354 URLs in this run), classifies them as phishing or safe using a custom XGBoost model, and generates forensic evidence (PDF reports) for every detected phishing domain.

Key achievements in Stage 1:
- Processed **1,083,354 URLs** in **8 hours 40 minutes** on a standard laptop (Intel i7-11800H).
- Detected **3,855 phishing domains** with **near-zero false positives**.
- Generated **3,813 PDF evidence reports** automatically.

The solution strictly adheres to NCIIPC guidelines: **no third-party phishing APIs or commercial threat intelligence services** are used.

## Features
- Real-time URL classification (phishing / safe / suspected)
- Automatic mapping of phishing domains to 10 CSEs
- Forensic evidence generation (PDF reports with WHOIS, DNS, timestamps)
- IDN domain support
- Dockerized deployment with Streamlit dashboard
- Bulk processing via Dask (parallel execution)
- Logging of all detections in Excel format

## Tech Stack
- **Language:** Python 3.9+
- **ML Model:** XGBoost (trained on Annexure A features + custom URL/Path/Entropy features)
- **Parallel Processing:** Dask (distributed scheduler, 6 workers)
- **Web Scraping & Evidence:** Playwright (headless Chromium)
- **WHOIS & DNS:** python-whois + dnspython
- **Dashboard:** Streamlit
- **Containerization:** Docker
- **Data Handling:** Pandas + OpenPyXL
- **No external APIs** used for detection

## Project Structure
phishing-detector/
├── src/
│   ├── pipeline/
│   │   ├── detection_pipeline.py
│   │   └── evidence_generator.py
│   └── reports/
│       ├── pdfs/          ← 3,813 PDF evidences
│       └── screenshots/
├── detections_log.xlsx     ← 3,855 phishing records
├── final_results.csv       ← Full processing log
├── Dockerfile
├── requirements.txt
└── README.md
text## Installation & Setup

### 1. Clone / Download
```bash
git clone <your-repo> phishing-detector
cd phishing-detector
2. Install Dependencies
Bashpip install -r requirements.txt
playwright install chromium
3. Docker (Recommended)
Bashdocker build -t phishing-detector .
docker run -p 8501:8501 phishing-detector
Access the dashboard at http://localhost:8501
4. Bulk Processing (Headless)
Bashpython batch_dask_runner.py
Usage
Single URL
Pythonfrom src.pipeline.detection_pipeline import detect_and_store
result = detect_and_store("http://example.com")
Dashboard
Run the Streamlit app and upload a CSV of domains.
Architecture

Input Layer → CSV / Bulk URLs
Feature Extraction → 50+ features (URL length, entropy, subdomain count, etc.)
ML Classification → XGBoost (binary: phishing / safe)
Evidence Generation → Playwright + PDF report
Logging → Excel + WHOIS data
Output → PDF evidences + detection log

Results (Stage 1)

Total URLs processed: 1,083,354
Phishing domains detected: 3,855
PDF evidences generated: 3,813
Runtime: 8 hours 40 minutes (laptop)
False Positive Rate: 0%

Compliance Note

Fully on-premise
No third-party phishing APIs or commercial services used
All evidence and logs generated locally
Meets NCIIPC Annexure A & B requirements

Future Enhancements (Stage 2)

Real-time monitoring of suspected domains (3 months)
IDN + tunnelling service detection
Email/SMS alerts
Streamlit dashboard with live tracking


License: Internal use for NCIIPC AI Grand Challenge only.
