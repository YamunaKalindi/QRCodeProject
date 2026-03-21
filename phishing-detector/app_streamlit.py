# app_streamlit.py
import os
import io
import asyncio
import tempfile
from datetime import datetime
import pandas as pd
import streamlit as st
from bson import ObjectId
from pymongo import MongoClient
from pathlib import Path

# try import your pipeline functions (adjust if path differs)
try:
    from src.pipeline.detection_pipeline import detect_and_store, load_models as _load_models  # for optional JIT model loading
    from src.pipeline.evidence_generator import generate_evidence
except Exception:
    # fallback to module import if running from different CWD
    from src.pipeline.detection_pipeline import detect_and_store, load_models as _load_models
    from src.pipeline.evidence_generator import generate_evidence

# ---------------------
# Config
# ---------------------
MONGO_URI = os.getenv("MONGO_URI",
                      "mongodb+srv://yamunabofficial_db_user:HareKrsna108@cluster0.goymkoi.mongodb.net/phishing_detector?retryWrites=true&w=majority&appName=Cluster0")
DB_NAME = os.getenv("DB_NAME", "phishing_detector")
DETECTED_COL = os.getenv("DETECTED_COL", "detected_domains")

# directories used by your evidence generator
BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "src" / "reports"
SCREENSHOT_DIR = REPORT_DIR / "screenshots"
PDF_DIR = REPORT_DIR / "pdfs"
EXCEL_PATH = BASE_DIR / "src" / "detections_log.xlsx"

# ---------------------
# Helpers
# ---------------------
@st.cache_resource
def get_mongo_client():
    client = MongoClient(MONGO_URI)
    return client

@st.cache_resource
def load_pipeline_models():
    """Load models once and reuse — calls your pipeline's loader (if available)."""
    try:
        models = _load_models()
        return models
    except Exception as e:
        st.warning("Could not auto-load models via pipeline.load_models(): " + str(e))
        return None

def fetch_recent_detections(limit=50):
    client = get_mongo_client()
    col = client[DB_NAME][DETECTED_COL]
    docs = list(col.find().sort("last_detected", -1).limit(limit))
    # convert ObjectId/time to strings for display
    rows = []
    for d in docs:
        rows.append({
            "url": d.get("url"),
            "domain": d.get("domain"),
            "prediction": d.get("global_prediction"),
            "confidence": d.get("global_confidence"),
            "cse": d.get("cse_prediction"),
            "last_detected": d.get("last_detected").isoformat() if isinstance(d.get("last_detected"), datetime) else str(d.get("last_detected")),
            "pdf": d.get("report_pdf") if "report_pdf" in d else None
        })
    return pd.DataFrame(rows)

def display_detection_result(result):
    st.subheader("Result")
    st.write("**URL:**", result["url"])
    st.write("**Domain:**", result["domain"])
    st.write("**Classification:**", result["global_prediction"])
    st.write("**Confidence:**", result["global_confidence"])
    st.write("**CSE Attribution:**", result.get("cse_prediction"))
    st.write("**Detected at:**", result.get("last_detected"))

    st.markdown("---")
    st.subheader("Features & Enrichment")
    df_feat = pd.DataFrame(list(result["features"].items()), columns=["feature", "value"])
    st.dataframe(df_feat)

    # screenshot & pdf
    screenshot_path = SCREENSHOT_DIR / f"{result['domain']}.png"
    pdf_path = PDF_DIR / f"{result['domain']}.pdf"

    if screenshot_path.exists():
        st.image(str(screenshot_path), caption="Captured screenshot", use_column_width=True)
        with open(screenshot_path, "rb") as fh:
            st.download_button("Download screenshot", fh.read(), file_name=f"{result['domain']}.png")

    if pdf_path.exists():
        with open(pdf_path, "rb") as fh:
            pdf_bytes = fh.read()
            st.download_button("Download PDF report", pdf_bytes, file_name=f"{result['domain']}.pdf")
            st.write(f"PDF saved at: `{pdf_path}`")

# ---------------------
# UI Layout
# ---------------------
st.set_page_config(page_title="Phishing Detector — Dashboard", layout="wide")
st.title("Phishing Detection & CSE Attribution — Dashboard")

col1, col2 = st.columns([2, 1])

with col1:
    st.header("Check a URL")
    input_url = st.text_input("Enter URL (including http/https). Example: https://example.com")
    run_btn = st.button("Run Detection")

    st.markdown("### Bulk upload")
    uploaded_file = st.file_uploader("Upload CSV with `url` column", type=["csv"])
    if uploaded_file:
        try:
            df_csv = pd.read_csv(uploaded_file)
            st.write("Preview uploaded CSV (first 5):")
            st.dataframe(df_csv.head())
            if "url" not in df_csv.columns:
                st.warning("CSV must contain a column named `url`.")
            else:
                if st.button("Ingest & Run on CSV"):
                    progress = st.progress(0)
                    total = len(df_csv)
                    results = []
                    for i, r in df_csv.iterrows():
                        url = r["url"]
                        res = detect_and_store(url)
                        # generate evidence (synchronously)
                        asyncio.run(generate_evidence(res))
                        results.append(res)
                        progress.progress(int((i+1)/total*100))
                    st.success(f"Processed {len(results)} rows")
        except Exception as ex:
            st.error("Failed to read CSV: " + str(ex))

    # manual run action
    if run_btn and input_url:
        with st.spinner("Running detection..."):
            # call detection pipeline
            res = detect_and_store(input_url.strip())
            # generate evidence (synchronously)
            asyncio.run(generate_evidence(res))
            st.success("Detection completed")
            display_detection_result(res)
    elif run_btn:
        st.warning("Provide a URL first.")

with col2:
    st.header("Recent detections (live)")
    df_recent = fetch_recent_detections(50)
    st.dataframe(df_recent)

    st.markdown("### Download logs")
    if EXCEL_PATH.exists():
        with open(EXCEL_PATH, "rb") as fh:
            st.download_button("Download detections_log.xlsx", fh.read(), file_name="detections_log.xlsx")
    else:
        st.info("No Excel log found yet.")

# footer: helpful utilities
st.markdown("---")
st.write("Model/DB status")
if st.button("Reload models & show info"):
    models = load_pipeline_models()
    st.write(models is not None and "global_model" in models)
    st.success("Reload complete (check logs)")

st.caption("Developed for PS-02 challenge — pipeline: global detector -> CSE attribution -> evidence generation.")
