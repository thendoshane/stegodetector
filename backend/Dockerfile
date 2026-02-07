# Use a lightweight Python image
FROM python:3.11-slim

# 1. Install system dependencies required for YARA
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Set working directory
WORKDIR /app

# 3. Copy dependencies and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy the application code
COPY . .

# 5. Define the command to run the app
# Cloud Run injects the PORT environment variable (default 8080)
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}