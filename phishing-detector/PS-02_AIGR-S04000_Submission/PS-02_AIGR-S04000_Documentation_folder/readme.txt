# AI Phishing Detection System - Dockerized Deployment

## Overview
This project is a multi-stage AI phishing URL and QR-code detection system which:
1. Detects phishing and safe URLs.
2. Maps phishing domains to Critical Sector Enterprises (CSEs).
3. Generates automated forensic evidence reports (screenshots, PDFs, and logs).

## Steps to Build and Run the Docker Container

### 1. Build Docker Image
Run the following command from your project root:
   docker build -t phishing-detector .

### 2. Run Container
Launch the container with:
   docker run -p 8501:8501 phishing-detector

The Streamlit app will be accessible at:
   http://localhost:8501

### 3. Environment Variables
Before running, ensure the following environment variables are configured:
   - MONGOURI (your MongoDB URI)
   - DBNAME (database name)
   - DETECTEDCOL (optional: collection name)

### 4. For Bulk Input or Headless Evidence Generation
You can also execute:
   docker exec -it phishing-detector python detection_pipeline.py
   docker exec -it phishing-detector python evidence_generator.py

### 5. Output
Generated PDF reports, screenshots, and logs will be saved in the './reports' directory inside the container.

System compatibility:
- Works with Linux, macOS, or Windows (Docker Desktop).
- Requires ~2 GB RAM and Python 3.9+.
