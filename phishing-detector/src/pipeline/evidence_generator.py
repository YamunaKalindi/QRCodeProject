# evidence_generator.py (REPLACE your current file with this)

import os
import asyncio
from datetime import datetime, timezone
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Image, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from playwright.async_api import async_playwright
import re
import urllib.parse

# === Directories ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
SCREENSHOT_DIR = os.path.join(REPORT_DIR, "screenshots")
PDF_DIR = os.path.join(REPORT_DIR, "pdfs")
EXCEL_PATH = os.path.join(BASE_DIR, "detections_log.xlsx")

for d in [REPORT_DIR, SCREENSHOT_DIR, PDF_DIR]:
    os.makedirs(d, exist_ok=True)


# === Helpers ===
def ensure_url_has_scheme(url: str) -> str:
    """If the URL has no scheme, prepend http:// to allow Playwright navigation."""
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "":
        return "http://" + url
    return url


def sanitize_filename(s: str, max_len: int = 180) -> str:
    """Make a safe filename from domain or url fragment."""
    s = s.strip().strip("/")  # remove surrounding whitespace and trailing slash
    # Replace invalid filename chars with underscore
    s = re.sub(r'[\\/*?:"<>|]', "_", s)
    # shorten long names
    if len(s) > max_len:
        s = s[:max_len]
    # If string is empty (paranoid), use timestamp
    if not s:
        s = datetime.utcnow().strftime("domain_%Y%m%d%H%M%S")
    return s


# === 1. Capture screenshot using Playwright ===
async def capture_screenshot(url: str, filename: str, timeout: int = 30000) -> str | None:
    """Capture screenshot with Playwright. Returns filename on success, None on failure."""
    safe_url = ensure_url_has_scheme(url)
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            # try multiple navigation strategies if needed
            await page.goto(safe_url, timeout=timeout, wait_until="load")
            # ensure directory exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            await page.screenshot(path=filename, full_page=True)
            await browser.close()
        return filename
    except Exception as e:
        # don't raise — return None so caller can continue
        print(f"[WARN] Screenshot failed for {safe_url}: {e}")
        return None


# === 2. Generate PDF report ===
def generate_pdf(result: dict, screenshot_path: str | None) -> str:
    domain_raw = str(result.get("domain", "unknown"))
    safe_name = sanitize_filename(domain_raw)
    pdf_path = os.path.join(PDF_DIR, f"{safe_name}.pdf")

    # Build document
    try:
        doc = SimpleDocTemplate(pdf_path, pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph(f"<b>Phishing Detection Report</b>", styles["Title"]))
        elements.append(Spacer(1, 0.18 * inch))

        summary_data = [
            ["URL", str(result.get("url", ""))],
            ["Domain", domain_raw],
            ["Global Classification", str(result.get("global_prediction", ""))],
            ["Confidence", f"{float(result.get('global_confidence', 0.0)):.3f}"],
            ["CSE Prediction", str(result.get("cse_prediction", "N/A"))],
            ["Detection Time", result.get("last_detected", datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S UTC")],
        ]
        summary_table = Table(summary_data, hAlign='LEFT', colWidths=[150, 350])
        summary_table.setStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ])
        elements.append(summary_table)
        elements.append(Spacer(1, 0.25 * inch))

        # Screenshot (if available)
        if screenshot_path and os.path.exists(screenshot_path):
            elements.append(Paragraph("<b>Website Screenshot:</b>", styles["Heading2"]))
            # scale image to fit page gracefully
            elements.append(Image(screenshot_path, width=6*inch, height=3*inch))
            elements.append(Spacer(1, 0.25 * inch))
        else:
            elements.append(Paragraph("<i>No screenshot available.</i>", styles["Normal"]))
            elements.append(Spacer(1, 0.15 * inch))

        # Domain info - present features/readable metadata
        elements.append(Paragraph("<b>Domain Features & Metadata</b>", styles["Heading2"]))
        features = result.get("features", {})
        feat_data = [[str(k), str(v)] for k, v in features.items()]
        if not feat_data:
            feat_data = [["note", "No features available"]]
        feat_table = Table(feat_data, hAlign='LEFT', colWidths=[150, 350])
        feat_table.setStyle([('GRID', (0, 0), (-1, -1), 0.25, colors.grey),])
        elements.append(feat_table)

        # finalize
        doc.build(elements)
        print(f"[INFO] PDF generated: {pdf_path}")
        return pdf_path

    except Exception as e:
        # If PDF creation fails, attempt a minimal fallback write
        print(f"[ERROR] PDF generation failed for {domain_raw}: {e}")
        fallback = os.path.join(PDF_DIR, f"{safe_name}_error.txt")
        with open(fallback, "w", encoding="utf-8") as fh:
            fh.write("PDF generation failed:\n")
            fh.write(str(e) + "\n\n")
            fh.write("Result snapshot:\n")
            fh.write(str(result))
        return fallback


# === 3. Save detection summary to Excel ===
def log_to_excel(result: dict, pdf_path: str, screenshot_path: str | None):
    record = {
        "URL": result.get("url"),
        "Domain": result.get("domain"),
        "Global Prediction": result.get("global_prediction"),
        "Confidence": result.get("global_confidence"),
        "CSE Prediction": result.get("cse_prediction"),
        "Report PDF": pdf_path,
        "Screenshot": screenshot_path,
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    df_new = pd.DataFrame([record])
    # If file exists, append; otherwise create
    if os.path.exists(EXCEL_PATH):
        try:
            df_old = pd.read_excel(EXCEL_PATH)
            df = pd.concat([df_old, df_new], ignore_index=True)
        except Exception as e:
            print(f"[WARN] Could not read existing Excel file, rewriting: {e}")
            df = df_new
    else:
        df = df_new

    df.to_excel(EXCEL_PATH, index=False)
    print(f"[INFO] Excel log updated: {EXCEL_PATH}")


# === 4. Unified Evidence Generation (async) ===
async def generate_evidence(result: dict):
    domain_raw = str(result.get("domain", "unknown"))
    safe_name = sanitize_filename(domain_raw)
    screenshot_path = os.path.join(SCREENSHOT_DIR, f"{safe_name}.png")

    screenshot = await capture_screenshot(result.get("url", ""), screenshot_path)
    pdf_path = generate_pdf(result, screenshot)
    log_to_excel(result, pdf_path, screenshot)
    return {"pdf": pdf_path, "screenshot": screenshot}


# === Convenience runner that is safe to call from sync code or from an existing event loop ===
def run_generate_evidence(result: dict):
    """Call this from sync code (works whether or not an event loop is running)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # schedule background task and return immediately
        # useful for Streamlit's running loop
        asyncio.create_task(generate_evidence(result))
        return None
    else:
        return asyncio.run(generate_evidence(result))


# === Example standalone run ===
if __name__ == "__main__":
    sample = {
        "url": "http://fakeicicibank-login.com",
        "domain": "fakeicicibank-login.com",
        "global_prediction": "phishing",
        "global_confidence": 0.87,
        "cse_prediction": "ICICI Bank",
        "features": {
            "url_length": 32, "entropy": 4.1, "subdomain_count": 1,
            "digit_ratio": 0.0, "special_chars": 0, "contains_ip": 0,
            "registrar": "GoDaddy", "country": "US", "ip_address": "93.184.216.34"
        },
        "last_detected": datetime.now(timezone.utc),
    }
    print("Running evidence generation (standalone)...")
    asyncio.run(generate_evidence(sample))
