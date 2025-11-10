# ShadowHunter GPU Analysis Service

GPU-accelerated malware analysis using Gemma 2 9B model.

## Features

- Gemma 2 9B model inference on NVIDIA L4 GPU
- Binary analysis integration with Ghidra service
- Text-based malware detection (Python, JS, PowerShell)
- Google Cloud Storage integration

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run service
python analyzer.py
```

## Cloud Deployment

```bash
# Build and deploy to Cloud Run with GPU
gcloud run deploy gpu-analyzer \
  --region us-central1 \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --memory 16Gi \
  --timeout 300
```

## Environment Variables

- `USE_GPU=true` - Enable GPU acceleration
- `MODEL_NAME=google/gemma-2-9b-it` - Model to use
- `GHIDRA_SERVICE_URL` - Ghidra service endpoint for binary analysis
- `PORT=8082` - Service port
