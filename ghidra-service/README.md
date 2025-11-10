# Ghidra Binary Analysis Service

Microservice for reverse engineering and decompiling binary executables.

## Features

- Ghidra 11.0 headless analysis
- Automatic decompilation of functions
- String extraction
- Import/Export table analysis
- Syscall detection
- Suspicious pattern identification

## Docker Build

```bash
docker build -t ghidra-service .
```

## Cloud Run Deployment

```bash
gcloud builds submit --tag gcr.io/PROJECT_ID/ghidra-service
gcloud run deploy ghidra-service \
  --image gcr.io/PROJECT_ID/ghidra-service \
  --region us-central1 \
  --memory 8Gi \
  --cpu 4 \
  --timeout 300
```

## API Endpoints

- `GET /health` - Health check
- `POST /analyze` - Analyze binary file

## Environment Variables

- `GHIDRA_PATH=/opt/ghidra` - Ghidra installation path
- `PORT=8081` - Service port
