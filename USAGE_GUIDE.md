# 📚 ShadowHunter AI - Usage Guide

**Complete guide for running, testing, and deploying ShadowHunter AI**

---

## 🚀 Quick Start (5 Minutes)

### For Local Development

```bash
# 1. Clone repository
git clone https://github.com/SherlockH0olms/Shadow.git
cd Shadow

# 2. Create .env file
cp .env.example .env
# Edit .env and add your VIRUSTOTAL_API_KEY

# 3. Run local startup script
chmod +x start_local.sh
./start_local.sh

# 4. Open browser
# Frontend: http://localhost:3000
# Backend API: http://localhost:8080/docs
```

That's it! The app is running locally.

---

## 📦 Installation

### Prerequisites

- **Python 3.9+** - [Download](https://www.python.org/downloads/)
- **Node.js 18+** - [Download](https://nodejs.org/)
- **Git** - [Download](https://git-scm.com/)

### Backend Setup

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install analyzer dependencies
pip install -r ../analyzer/requirements.txt
```

### Frontend Setup

```bash
cd frontend

# Install npm packages
npm install
```

---

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Required
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Optional (for cloud deployment)
GOOGLE_CLOUD_PROJECT=your-project-id
BACKEND_SERVICE_URL=
GPU_SERVICE_URL=
GEMINI_API_KEY=

# Local mode
CLOUD_MODE=false
LOCAL_STORAGE_PATH=./storage
```

### Getting API Keys

#### VirusTotal API Key (Required)
1. Go to [VirusTotal](https://www.virustotal.com/)
2. Sign up for free account
3. Go to Profile → API Key
4. Copy your API key

#### Gemini API Key (Optional)
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create new API key
3. Add to `.env`

---

## 🎯 Running the Application

### Option 1: Auto Start (Recommended)

```bash
./start_local.sh
```

This script:
- ✅ Sets up Python virtual environment
- ✅ Installs all dependencies
- ✅ Starts backend on port 8080
- ✅ Starts frontend on port 3000
- ✅ Shows logs in real-time

### Option 2: Manual Start

**Terminal 1 - Backend:**
```bash
cd backend
source venv/bin/activate
python3 main.py
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

---

## 🧪 Testing

### 1. Test Pattern Detector

```bash
cd analyzer
python3 patterns.py
```

Expected output:
```
ShadowHunter AI - Pattern Detector Test
AI Generated: True
LLM Source: deepseek
Confidence: 87%
Risk Score: 85/100
```

### 2. Test YARA Scanner

```bash
cd analyzer
python3 yara_scanner.py
```

### 3. Test with Sample Files

```bash
python3 test_local.py
```

This runs all 4 test samples:
- ✅ deepseek_generated_malware.py (should detect)
- ✅ gpt4_generated_malware.py (should detect)
- ✅ claude_generated_code.py (should detect)
- ✅ clean_sample.py (should NOT detect)

### 4. API Testing

With backend running:

```bash
# Health check
curl http://localhost:8080/health

# Analyze file
curl -X POST "http://localhost:8080/api/analyze" \
  -F "file=@tests/samples/deepseek_generated_malware.py"
```

---

## 📊 Using the Web Interface

### 1. Upload File

1. Open http://localhost:3000
2. Drag & drop file or click to browse
3. Supported formats:
   - Python (.py)
   - JavaScript (.js)
   - PowerShell (.ps1)
   - Executables (.exe, .dll)

### 2. View Results

After analysis, you'll see:

- **Verdict**: MALWARE DETECTED or FILE APPEARS CLEAN
- **Confidence Score**: 0-100%
- **Risk Score**: 0-100
- **LLM Source**: DeepSeek, GPT-4, Claude, or Unknown
- **Detected Patterns**: List of AI signatures found
- **Evasion Techniques**: Anti-analysis methods detected
- **Malicious Functions**: Suspicious API calls
- **YARA Matches**: Matched YARA rules

### 3. Analysis Details

- **Entropy**: File randomness (higher = more obfuscated)
- **Obfuscation Level**: None, Medium, or High
- **File Hash**: SHA256 hash
- **File Size**: In KB/MB

---

## ☁️ Cloud Deployment

### Prerequisites

1. **Google Cloud Account** with billing enabled
2. **GPU Quota** - [Request here](https://run.devpost.com/resources)
3. **gcloud CLI** - [Install](https://cloud.google.com/sdk/docs/install)

### Deploy to Google Cloud Run

```bash
# 1. Login to gcloud
gcloud auth login

# 2. Set project
gcloud config set project YOUR_PROJECT_ID

# 3. Run deployment script
chmod +x deploy.sh
./deploy.sh

# 4. Select what to deploy:
#    1) Backend API only
#    2) GPU Service only (requires GPU quota)
#    3) Both services
```

### After Deployment

1. Copy the service URLs shown
2. Update `.env` file:
   ```env
   BACKEND_SERVICE_URL=https://backend-api-xxx.run.app
   GPU_SERVICE_URL=https://gpu-analyzer-xxx.run.app
   ```

3. Test deployed services:
   ```bash
   curl https://backend-api-xxx.run.app/health
   ```

---

## 🔍 API Reference

### Endpoints

#### `GET /`
Root endpoint - API information

```bash
curl http://localhost:8080/
```

Response:
```json
{
  "service": "ShadowHunter AI Backend",
  "status": "healthy",
  "version": "1.0.0",
  "mode": "local"
}
```

#### `GET /health`
Health check with service status

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "mode": "local",
  "analyzers": {
    "pattern_detector": true,
    "yara_scanner": true
  },
  "cloud_services": {
    "storage": false,
    "firestore": false,
    "gpu_service": false
  }
}
```

#### `POST /api/analyze`
Analyze file for malware

```bash
curl -X POST "http://localhost:8080/api/analyze" \
  -F "file=@path/to/file.py" \
  -H "Content-Type: multipart/form-data"
```

Response:
```json
{
  "file_id": "uuid",
  "file_name": "malware.py",
  "file_hash": "sha256...",
  "file_size": 1234,
  "status": "completed",
  "is_malicious": true,
  "confidence": 0.87,
  "risk_score": 85,
  "llm_source": "deepseek",
  "detected_patterns": ["CRYSTALS-Kyber", "quantum_encrypt"],
  "evasion_techniques": ["Polymorphic entropy generation"],
  "malicious_indicators": ["WriteProcessMemory"],
  "yara_matches": [...],
  "created_at": "2025-11-10T19:00:00",
  "completed_at": "2025-11-10T19:00:25"
}
```

#### `GET /api/status/{file_id}`
Get analysis status

```bash
curl http://localhost:8080/api/status/uuid
```

#### `GET /api/history?limit=10`
Get recent analysis history

```bash
curl "http://localhost:8080/api/history?limit=10"
```

---

## 🎬 Demo Scenarios

### Scenario 1: Detecting DeepSeek Malware

1. Upload `tests/samples/deepseek_generated_malware.py`
2. Wait ~5 seconds
3. See detection:
   - ✅ Malware Detected
   - Confidence: 87%
   - LLM Source: DeepSeek
   - Patterns: CRYSTALS-Kyber, quantum_encrypt

### Scenario 2: Comparing with VirusTotal

1. Analyze file with ShadowHunter: **DETECTED**
2. Check same file on VirusTotal: **0/63 engines**
3. Show superiority of AI-specific detection

### Scenario 3: Clean File Validation

1. Upload `tests/samples/clean_sample.py`
2. See result:
   - ✅ File Appears Clean
   - Confidence: 0%
   - Risk Score: 0

---

## 🐛 Troubleshooting

### Backend won't start

**Error**: `ModuleNotFoundError: No module named 'fastapi'`

**Solution**:
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
```

### YARA scanner not working

**Error**: `yara-python not installed`

**Solution**:
```bash
pip install yara-python==4.3.1
```

### Frontend build fails

**Error**: `Cannot find module 'react'`

**Solution**:
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### Port already in use

**Error**: `Address already in use: 8080`

**Solution**:
```bash
# Find process
lsof -i :8080

# Kill it
kill -9 PID
```

---

## 📈 Performance Optimization

### Local Development

- **Disable YARA**: Set `YARA_ENABLED=false` in .env for faster testing
- **Cache Results**: Results are cached in `storage/results/`
- **Skip VirusTotal**: Leave `VIRUSTOTAL_API_KEY` empty

### Production

- **Enable Cloud Mode**: `CLOUD_MODE=true`
- **Use GPU Service**: Deploy GPU service for 10x faster analysis
- **CDN for Frontend**: Deploy frontend to Vercel/Netlify

---

## 🔐 Security Best Practices

1. **Never commit .env file** - Always in .gitignore
2. **Rotate API keys regularly** - Every 90 days
3. **Use service accounts** - For cloud deployment
4. **Scan uploaded files in sandbox** - Isolated environment
5. **Rate limit API** - Prevent abuse

---

## 📞 Support

- 📧 **Email**: support@shadowhunter-ai.com
- 🐛 **Issues**: [GitHub Issues](https://github.com/SherlockH0olms/Shadow/issues)
- 📖 **Documentation**: See README.md and ARCHITECTURE.md

---

**Built with ❤️ for Cloud Run Hackathon 2025**
