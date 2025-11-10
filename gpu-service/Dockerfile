FROM nvidia/cuda:12.1.0-base-ubuntu22.04

# Install Python and dependencies
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python packages
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY analyzer.py .

# Environment
ENV PORT=8082
ENV USE_GPU=true
ENV MODEL_NAME=google/gemma-2-9b-it

EXPOSE 8082

# Start service
CMD ["python3", "analyzer.py"]
