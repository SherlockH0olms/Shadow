FROM nvidia/cuda:12.1.0-cudnn8-runtime-ubuntu22.04

# Install Python and system dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    git \
    wget \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.11 as default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1
RUN update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY analyzer.py .

# Copy analyzer and integrations modules from parent directory
COPY ../analyzer /app/analyzer
COPY ../integrations /app/integrations

# Copy service account key if exists
COPY ../service-account-key.json* ./ || true

# Environment variables
ENV PORT=8080
ENV PYTHONUNBUFFERED=1
ENV USE_GPU=true
ENV MODEL_NAME=google/gemma-2-9b-it

# Pre-download model (optional - can also download at runtime)
# RUN python -c "from transformers import AutoTokenizer, AutoModelForCausalLM; AutoTokenizer.from_pretrained('google/gemma-2-9b-it'); print('Tokenizer downloaded')"

EXPOSE 8080

# Run the application
CMD exec uvicorn analyzer:app --host 0.0.0.0 --port ${PORT} --workers 1 --timeout-keep-alive 300
