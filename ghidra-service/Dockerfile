FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    wget \
    unzip \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Download and install Ghidra
WORKDIR /opt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip && \
    unzip ghidra_11.0_PUBLIC_20231222.zip && \
    rm ghidra_11.0_PUBLIC_20231222.zip && \
    mv ghidra_11.0_PUBLIC ghidra

# Install Python packages
RUN pip3 install fastapi uvicorn httpx google-cloud-storage

# Copy application files
COPY analyze_binary.py /app/
COPY ghidra_script.py /app/

WORKDIR /app

# Environment
ENV PORT=8081
ENV GHIDRA_PATH=/opt/ghidra
ENV PYTHONUNBUFFERED=1

EXPOSE 8081

# Start service
CMD ["uvicorn", "analyze_binary:app", "--host", "0.0.0.0", "--port", "8081"]
