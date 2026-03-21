# -------------------------------
# Stage 1: Base Image
# -------------------------------
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    curl \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------------
# Environment Configuration
# -------------------------------
ENV PYTHONUNBUFFERED=1
ENV MONGOURI="your_mongodb_connection_uri"
ENV DBNAME="phishingdetector"

# Ensure playwright dependencies work (for screenshots)
RUN playwright install --with-deps chromium

# -------------------------------
# Expose port and run app
# -------------------------------
EXPOSE 8501

CMD ["streamlit", "run", "app_streamlit.py", "--server.port=8501", "--server.address=0.0.0.0"]
