import os
import re
from unittest import result
import numpy as np
import socket
import dns.resolver
import whois
from urllib.parse import urlparse
from datetime import datetime
from ipwhois import IPWhois
from pymongo import MongoClient
import joblib
import tensorflow as tf
import lightgbm as lgb
from statistics import mean
import random

from src.pipeline.evidence_generator import generate_evidence
import asyncio


import asyncio
if os.name == "nt":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())



# === Feature Functions (used by loader too) ===
def calculate_entropy(url):
    counts = {c: url.count(c) for c in set(url)}
    total = len(url)
    return -sum((count/total) * np.log2(count/total)
                for count in counts.values()) if total > 0 else 0

def subdomain_count(url):
    return urlparse(url).netloc.count('.')

def digit_ratio(url):
    return sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0

def special_char_count(url):
    return sum(c in '@?&=' for c in url)

def contains_ip(url):
    return int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))

def has_https(url):
    return int(url.lower().startswith("https"))


# === MongoDB Connection ===
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb+srv://yamunabofficial_db_user:HareKrsna108@cluster0.goymkoi.mongodb.net/phishing_detector?retryWrites=true&w=majority&appName=Cluster0"
)
client = MongoClient(MONGO_URI)
db = client["phishing_detector"]
detected_col = db["detected_domains"]
cse_col = db["cse_domains"]

# === Load Models & Preprocessors ===
# === Load Models & Preprocessors ===
def load_models():
    print("[INFO] Loading models...")

    # base_model_dir = os.getenv("MODEL_DIR", "C:/Users/achyu/Documents/phishing-detector/src/model/models")
    stage2_model_dir = os.getenv("STAGE2_DIR", "C:/Users/achyu/Documents/phishing-detector/src/model/models_stage2")

    # --- Stage 1 global ANN & scaler (user path may vary)
    base_model_dir = os.getenv("MODEL_DIR", "C:/Users/achyu/Documents/phishing-detector/models")
    global_model_path = os.path.join(base_model_dir, "qr_url_detector_model.keras")
    global_scaler_path = os.path.join(base_model_dir, "url_scaler.pkl")


    global_model = tf.keras.models.load_model(global_model_path)
    global_scaler = joblib.load(global_scaler_path)
    print(f"[INFO] Loaded Stage-1 model from: {global_model_path}")

    # --- Stage 2 LightGBM + preprocessors (existing)
    stage2_model_path = os.path.join(stage2_model_dir, "lgb_final.txt")
    stage2_model = lgb.Booster(model_file=stage2_model_path)

    stage2_labelenc = joblib.load(os.path.join(stage2_model_dir, "label_encoder.joblib"))
    stage2_scaler = joblib.load(os.path.join(stage2_model_dir, "scaler.joblib"))
    stage2_imputer = joblib.load(os.path.join(stage2_model_dir, "imputer.joblib"))
    stage2_feature_cols = joblib.load(os.path.join(stage2_model_dir, "feature_cols.joblib"))

    models_dict = {
        "global_model": global_model,
        "global_scaler": global_scaler,
        "stage2_model": stage2_model,
        "stage2_labelenc": stage2_labelenc,
        "stage2_scaler": stage2_scaler,
        "stage2_imputer": stage2_imputer,
        "stage2_feature_cols": stage2_feature_cols
    }

    # --- Quick polarity detection for Stage-1: check whether higher prob -> phishing or -> safe
    try:
        print("[INFO] Determining Stage-1 probability polarity (this runs a few predictions)...")
        # 1) a small set of known safe URLs (common legit domains)
        safe_samples = [
            "https://www.google.com",
            "https://www.microsoft.com",
            "https://www.icicibank.com",
            "https://www.hdfcbank.com",
            "https://www.amazon.in"
        ]

        # 2) sample phishing URLs from your training collection (if present)
        phishing_samples = []
        try:
            # try gathering some labeled phishing records from training_data collection
            cursor = db["training_data"].find({"Phishing/Suspected Domains (i": {"$exists": True}}, {"Identified Phishing/Suspected Domain Name": 1}).limit(200)
            for doc in cursor:
                # doc keys are messy in your DB, try multiple possible fields
                url = None
                if "Identified Phishing/Suspected Domain Name" in doc:
                    url = doc["Identified Phishing/Suspected Domain Name"]
                elif "url" in doc:
                    url = doc["url"]
                if url:
                    # ensure it's a proper scheme
                    if not urlparse(url).scheme:
                        url = "http://" + url
                    phishing_samples.append(url)
            # if not enough, fallback to a small hardcoded list
        except Exception:
            pass

        if len(phishing_samples) < 10:
            # fallback short phishing examples
            phishing_samples = [
                "http://fakeicicibank-login.com",
                "http://secure-sbi-verify.com",
                "http://id-updation-hdfcbank.net",
                "http://paytm-secure-login.co"
            ]

        # sample up to N from each
        N = 10
        safe_subset = random.sample(safe_samples, min(N, len(safe_samples)))
        phishing_subset = random.sample(phishing_samples, min(N, len(phishing_samples)))

        def _pred_prob(url):
            # same extraction used in pipeline
            feats = np.array([
                len(url),
                calculate_entropy(url),
                subdomain_count(url),
                digit_ratio(url),
                special_char_count(url),
                contains_ip(url)
            ]).reshape(1, -1)
            scaled = global_scaler.transform(feats)
            prob = float(global_model.predict(scaled)[0][0])
            return prob

        safe_probs = [_pred_prob(u) for u in safe_subset]
        phish_probs = [_pred_prob(u) for u in phishing_subset]

        mean_safe = mean(safe_probs) if safe_probs else 0.0
        mean_phish = mean(phish_probs) if phish_probs else 0.0

        print(f"[INFO] mean_prob(safe_sample)   = {mean_safe:.4f}")
        print(f"[INFO] mean_prob(phish_sample)  = {mean_phish:.4f}")

        # Decide polarity:
        # - if mean_phish > mean_safe => model outputs higher prob for phishing (phishing_high)
        # - else => model outputs higher prob for safe (phishing_low) -> invert logic
        if mean_phish > mean_safe:
            models_dict["stage1_polarity"] = "phishing_high"
            print("[INFO] Stage-1 model polarity => HIGH probability indicates PHISHING.")
        else:
            models_dict["stage1_polarity"] = "phishing_low"
            print("[INFO] Stage-1 model polarity => HIGH probability indicates SAFE. (will invert)")

    except Exception as e:
        print("[WARN] Could not auto-detect stage1 polarity:", e)
        # default to previous assumption (high->phishing) but warn
        models_dict["stage1_polarity"] = "phishing_high"

    return models_dict

models = load_models()

# === Feature Functions ===
def calculate_entropy(url):
    counts = {c: url.count(c) for c in set(url)}
    total = len(url)
    return -sum((count/total) * np.log2(count/total) for count in counts.values()) if total > 0 else 0

def subdomain_count(url):
    return urlparse(url).netloc.count('.')

def digit_ratio(url):
    return sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0

def special_char_count(url):
    return sum(c in '@?&=' for c in url)

def contains_ip(url):
    return int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))

def enrich_domain(domain):
    info = {"creation_date": None, "registrar": None, "country": None,
            "mx_records": [], "ip_address": None, "asn": None}
    try:
        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            info["creation_date"] = str(w.creation_date[0])
        elif w.creation_date:
            info["creation_date"] = str(w.creation_date)
        info["registrar"] = w.registrar
        info["country"] = w.country
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        info["mx_records"] = [str(r.exchange) for r in answers]
    except Exception:
        pass

    try:
        ip_address = socket.gethostbyname(domain)
        info["ip_address"] = ip_address
        if ip_address:
            try:
                obj = IPWhois(ip_address)
                results = obj.lookup_rdap()
                info["asn"] = results.get("asn_org", None)
            except Exception:
                pass
    except Exception:
        pass

    return info

# === Detection Pipeline ===
def detect_and_store(raw_url):
    parsed = urlparse(raw_url)
    domain = parsed.netloc or raw_url

    # --- Feature extraction
    features = {
        "url_length": len(raw_url),
        "entropy": calculate_entropy(raw_url),
        "subdomain_count": subdomain_count(raw_url),
        "digit_ratio": digit_ratio(raw_url),
        "special_chars": special_char_count(raw_url),
        "contains_ip": contains_ip(raw_url),
    }
    features.update(enrich_domain(domain))

    # --- Stage 1: Global model (Phishing vs Safe)
    arr = np.array([
        features["url_length"],
        features["entropy"],
        features["subdomain_count"],
        features["digit_ratio"],
        features["special_chars"],
        features["contains_ip"]
    ]).reshape(1, -1)

    arr_scaled = models["global_scaler"].transform(arr)
    prob = float(models["global_model"].predict(arr_scaled)[0][0])
    polarity = models.get("stage1_polarity", "phishing_high")
    TH = float(os.getenv("STAGE1_THRESHOLD", 0.5))  # default 0.5

    if polarity == "phishing_high":
        global_label = "phishing" if prob >= TH else "safe"
    else:
        # model's high prob means safe → invert
        global_label = "phishing" if prob <= (1 - TH) else "safe"

    # Normalize confidence for consistent display
    if polarity == "phishing_low":
        display_conf = 1 - prob if global_label == "phishing" else prob
    else:
        display_conf = prob
    display_conf = round(float(display_conf), 3)

    # --- Stage 2: CSE attribution (only if phishing)
    stage2_label = None
    try:
        if global_label == "phishing":
            row = {col: features.get(col, None) for col in models["stage2_feature_cols"]}
            row = models["stage2_imputer"].transform([list(row.values())])
            row = models["stage2_scaler"].transform(row)

            pred_proba = models["stage2_model"].predict(row)
            pred_label = np.argmax(pred_proba, axis=1)
            stage2_label = models["stage2_labelenc"].inverse_transform(pred_label)[0]
    except Exception as e:
        print(f"[WARN] Stage-2 attribution skipped: {e}")
        stage2_label = None

    # --- Construct result (always)
    result = {
        "url": raw_url,
        "domain": domain,
        "global_prediction": global_label,
        "global_confidence": display_conf,
        "cse_prediction": stage2_label,
        "features": features,
        "last_detected": datetime.utcnow()
    }

    # --- Store in Mongo
    try:
        detected_col.insert_one(result)
    except Exception as e:
        print(f"[WARN] Could not insert into MongoDB: {e}")

    return result




# === Example CLI usage ===
if __name__ == "__main__":
    test_url = os.getenv("TEST_URL", "http://fakeicicibank-login.com")
    res = detect_and_store(test_url)
    print(res)
    asyncio.run(generate_evidence(res))
