import os
import asyncio
import dask.dataframe as dd
import pandas as pd
from dask.distributed import Client
from dask.diagnostics import ProgressBar
from datetime import datetime, timezone
from urllib.parse import urlparse
import whois
import socket
import aiohttp
import time
from src.pipeline.detection_pipeline import detect_and_store
from src.pipeline.evidence_generator import generate_evidence

# === CONFIG ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PART1 = os.path.join(BASE_DIR, "Shortlisting_Data_Part_1.xlsx")
PART2 = os.path.join(BASE_DIR, "Shortlisting_Data_Part_2.xlsx")
TEMP1 = os.path.join(BASE_DIR, "temp_part1.csv")
TEMP2 = os.path.join(BASE_DIR, "temp_part2.csv")
OUTPUT_CSV = os.path.join(BASE_DIR, "final_results.csv")

# Ensure reports directory exists
PDF_DIR = os.path.join(BASE_DIR, "src", "reports", "pdfs")
SCREENSHOT_DIR = os.path.join(BASE_DIR, "src", "reports", "screenshots")
os.makedirs(PDF_DIR, exist_ok=True)
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# Global lists for batching
phishing_results = []
detection_logs = []

# Dask meta for map_partitions
META = {
    "URL": str,
    "Domain": str,
    "Global Prediction": str,
    "Confidence": float,
    "CSE Prediction": str,
    "Timestamp": str,
    "Error": str
}

def safe_url(domain):
    """Ensure valid URL format."""
    domain = str(domain).strip()
    if not domain or domain.lower() == 'nan':
        return None
    if not domain.startswith(("http://", "https://")):
        domain = "http://" + domain
    return domain

async def safe_whois(domain):
    """Perform WHOIS lookup with timeout."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(whois.whois, domain),
            timeout=5
        )
    except asyncio.TimeoutError:
        print(f"[WARN] WHOIS timed out for {domain}")
        return {"error": "WHOIS timeout"}
    except socket.gaierror:
        print(f"[WARN] WHOIS failed for {domain}: getaddrinfo failed")
        return {"error": "DNS resolution failed"}
    except Exception as e:
        print(f"[WARN] WHOIS error for {domain}: {str(e)}")
        return {"error": str(e)}

async def fetch_screenshot(url):
    """Fetch webpage content with timeout."""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                return await response.text()
        except Exception as e:
            print(f"[WARN] Screenshot failed for {url}: {str(e)}")
            return None

async def wrapped_generate_evidence(result):
    """Wrapper for generate_evidence with network handling."""
    try:
        domain = result["domain"]
        url = result["url"]
        whois_data = await safe_whois(domain)
        html = await fetch_screenshot(url)
        await asyncio.wait_for(generate_evidence(result), timeout=10)
        return True
    except asyncio.TimeoutError:
        print(f"[WARN] Evidence generation timed out for {url}")
        return False
    except Exception as e:
        print(f"[WARN] Evidence generation failed for {url}: {str(e)}")
        return False

def process_single(row):
    """Run detection on a single domain."""
    start_time = time.time()
    url = safe_url(row["Domain User Form"])
    if not url:
        return {"URL": "N/A", "Error": "Invalid domain", "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}

    try:
        # Run detection pipeline
        detect_start = time.time()
        result = detect_and_store(url)
        detect_time = time.time() - detect_start

        # Queue evidence for phishing URLs
        evidence_time = 0
        if result["global_prediction"] == "phishing":
            evidence_start = time.time()
            success = asyncio.run(wrapped_generate_evidence(result))
            evidence_time = time.time() - evidence_start
            if success:
                phishing_results.append(result)
            detection_logs.append({
                "URL": result["url"],
                "Prediction": result["global_prediction"],
                "Confidence": result["global_confidence"],
                "CSE Prediction": result.get("cse_prediction", "N/A"),
                "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "Error": "None" if success else "Evidence generation failed or timed out",
            })

        total_time = time.time() - start_time
        print(f"[PROFILING] URL: {url}, Detect: {detect_time:.2f}s, Evidence: {evidence_time:.2f}s, Total: {total_time:.2f}s")
        return {
            "URL": result["url"],
            "Domain": result["domain"],
            "Global Prediction": result["global_prediction"],
            "Confidence": result["global_confidence"],
            "CSE Prediction": result.get("cse_prediction", "N/A"),
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "Error": "None"
        }

    except Exception as e:
        total_time = time.time() - start_time
        print(f"[ERROR] URL: {url}, Error: {str(e)}, Total: {total_time:.2f}s")
        detection_logs.append({
            "URL": url,
            "Prediction": "error",
            "Confidence": 0.0,
            "CSE Prediction": "N/A",
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "Error": str(e),
        })
        return {"URL": url, "Error": str(e), "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}

def main():
    start_time = time.time()
    # Convert Excel to CSV (only if not already done)
    if not os.path.exists(TEMP1):
        print("[INFO] Converting Part 1 Excel → CSV...")
        pd.read_excel(PART1, usecols=["Domain User Form"]).to_csv(TEMP1, index=False)

    if not os.path.exists(TEMP2):
        print("[INFO] Converting Part 2 Excel → CSV...")
        pd.read_excel(PART2, usecols=["Domain User Form"]).to_csv(TEMP2, index=False)

    print("[INFO] Loading CSV files with Dask...")
    df1 = dd.read_csv(TEMP1, blocksize="8MB")
    df2 = dd.read_csv(TEMP2, blocksize="8MB")
    df = dd.concat([df1, df2], axis=0).drop_duplicates()

    print(f"[INFO] Total domains to process: {len(df)}")

    # Use Dask distributed scheduler
    client = Client(n_workers=6, threads_per_worker=1, memory_limit="4GB")
    print("[INFO] Dask distributed client started:", client)

    # Process URLs in parallel with periodic checkpointing
    results = []
    checkpoint_interval = 10  # Save every ~10 partitions
    for i, partition in enumerate(df.partitions):
        partition_results = partition.apply(process_single, axis=1, meta=META).compute()
        results.extend(partition_results)
        if (i + 1) % checkpoint_interval == 0:
            print(f"[INFO] Saving partial results at partition {i+1}...")
            pd.DataFrame([r for r in results if r is not None]).to_csv(
                f"partial_results_{i+1}.csv", index=False
            )

    # Generate PDFs and logs in bulk
    print("[INFO] Generating PDFs and logs for phishing URLs...")
    for result in phishing_results:
        success = asyncio.run(wrapped_generate_evidence(result))
        if not success:
            detection_logs.append({
                "URL": result["url"],
                "Prediction": result["global_prediction"],
                "Confidence": result["global_confidence"],
                "CSE Prediction": result.get("cse_prediction", "N/A"),
                "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "Error": "Evidence generation failed or timed out in bulk processing",
            })

    # Write detection logs
    if detection_logs:
        print("[INFO] Writing detection logs to Excel...")
        pd.DataFrame(detection_logs).to_excel(os.path.join(BASE_DIR, "src", "detections_log.xlsx"), index=False)

    # Save final results
    out_df = pd.DataFrame([r for r in results if r is not None])
    out_df.to_csv(OUTPUT_CSV, index=False)
    print(f"[INFO] Results saved to {OUTPUT_CSV}")
    print(f"[INFO] Total runtime: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    # Disable oneDNN warning
    os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
    main()