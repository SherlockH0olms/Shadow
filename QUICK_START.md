# ⚡ ShadowHunter AI - Quick Start Guide

## 🎯 Hackathon Checklist - İlk 30 Dəqiqə

### ✅ 1. API Açarlarını Əldə Edin (10 dəqiqə)

```bash
# 1️⃣ VirusTotal API (PULSUZ)
# https://www.virustotal.com/gui/my-apikey
# Sign up → Copy API key

# 2️⃣ Google Cloud
# https://console.cloud.google.com/
# Yeni layihə yarat → API-ləri aktiv et

# 3️⃣ GPU Quota Tələbi (ƏN VACİB!)
# https://run.devpost.com/resources
# "Request GPU Access" → Form doldur
```

### ✅ 2. Proyekti Hazırlayın (5 dəqiqə)

```bash
cd /home/kali/Desktop/ShadowHunterAI

# .env yaradın
cp .env.example .env

# API açarlarınızı əlavə edin
nano .env
```

**.env faylında dəyişdirin:**
```bash
PROJECT_ID=shadowhunter-ai-YOUR-NAME-2025  # Unikal ad
VIRUSTOTAL_API_KEY=BURAYA_SIZIN_AÇARINIZ
GEMINI_API_KEY=BURAYA_SIZIN_AÇARINIZ  # (opsional)
```

### ✅ 3. İnfrastrukturu Qurun (15 dəqiqə)

```bash
# Google Cloud setup
./setup.sh

# Bu yaradacaq:
# - Cloud Storage buckets
# - Firestore database
# - Service account
# - API aktivləşdirmə
```

---

## 🧪 Lokal Test (GPU Gözləyərkən)

GPU quota təsdiqi 2-4 saat çəkir. Bu müddətdə local test edin:

### Pattern Detector Test:

```bash
cd analyzer
python3 patterns.py
```

**Gözlənilən output:**
```
Analysis Result:
  AI Generated: True
  LLM Source: deepseek
  Confidence: 85.00%
  Risk Score: 60
```

### YARA Scanner Test:

```bash
cd analyzer
python3 yara_scanner.py
```

**Gözlənilən output:**
```
Detected 3 YARA rule matches:
  Rule: AI_Generated_Malware_DeepSeek
  Severity: high
```

### Test Samples İlə:

```bash
# DeepSeek sample test
python3 -c "
from analyzer.patterns import AICodePatternDetector
detector = AICodePatternDetector()
with open('tests/samples/deepseek_generated_malware.py') as f:
    result = detector.analyze(f.read())
print(f'AI Generated: {result[\"is_ai_generated\"]}')
print(f'Confidence: {result[\"confidence\"]:.2%}')
"
```

---

## 🚀 Deployment (GPU Quota Təsdiq Olunanda)

### Backend Deploy:

```bash
./deploy.sh
# Seçin: "1) Backend API only"
```

**5-10 dəqiqə çəkəcək.** Sonunda URL alacaqsınız:
```
✅ Backend API deployed!
URL: https://backend-api-xxxxx-ew.a.run.app
```

### GPU Service Deploy:

```bash
./deploy.sh
# Seçin: "2) GPU Service only"
```

**10-15 dəqiqə çəkəcək** (model böyükdür).

---

## ✅ Test Edin

```bash
# .env faylında URL-ləri yeniləyin
nano .env
# BACKEND_SERVICE_URL və GPU_SERVICE_URL əlavə edin

# Test skriptini işə salın
./test_api.sh
```

**Gözlənilən output:**
```
✅ Health check passed
✅ Analysis completed
✅ AI-generated malware detected correctly!
🎉 Testing Complete!
```

---

## 📊 Demo Üçün

### 1. Test Samples:
- ✅ `tests/samples/deepseek_generated_malware.py` - DeepSeek pattern
- ✅ `tests/samples/gpt4_generated_malware.py` - GPT-4 pattern
- ✅ `tests/samples/claude_generated_code.py` - Claude pattern
- ✅ `tests/samples/clean_sample.py` - Clean (false positive test)

### 2. API İstifadə Nümunəsi:

```bash
# Fayl analizi
curl -X POST https://YOUR-BACKEND-URL/api/analyze \
  -F "file=@tests/samples/deepseek_generated_malware.py"

# Tarixçə
curl https://YOUR-BACKEND-URL/api/history
```

### 3. Nəticə Nümunəsi:

```json
{
  "detection": {
    "is_malicious": true,
    "is_ai_generated": true,
    "confidence": 0.94,
    "llm_source": "deepseek"
  },
  "pattern_analysis": {
    "detected_patterns": [
      "CRYSTALS-Kyber",
      "quantum_encrypt",
      "polymorphic"
    ],
    "risk_score": 85
  },
  "yara_matches": [
    {
      "rule": "AI_Generated_Malware_DeepSeek",
      "severity": "high"
    }
  ],
  "virustotal": {
    "exists": false,
    "message": "Not found in VirusTotal (0/63 detection)"
  },
  "risk_assessment": {
    "risk_level": "HIGH",
    "recommended_action": "QUARANTINE"
  }
}
```

---

## 🎥 Demo Video Üçün Ssenari

**1. Problem (30 saniyə):**
- "Traditional AV fails against AI-generated malware"
- VirusTotal screenshot: 0/63
- "DeepSeek, GPT-4, Claude can create undetectable threats"

**2. Həll (30 saniyə):**
- "ShadowHunter AI - First specialized detector"
- Architecture diagram
- "GPU-powered, real-time analysis"

**3. Live Demo (60 saniyə):**
- File upload (DeepSeek sample)
- Real-time analysis
- **RESULT: DETECTED (94% confidence)**
- Compare: VirusTotal 0/63 vs ShadowHunter ✅

**4. Tech Stack (30 saniyə):**
- Cloud Run + L4 GPU
- Gemma 2 9B model
- YARA rules + Pattern detection
- "Production-ready in 48 hours"

---

## 🐛 Ən Çox Rast Gəlinən Problemlər

### "Permission denied"
```bash
chmod +x setup.sh deploy.sh test_api.sh
```

### "gcloud: command not found"
```bash
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
```

### "GPU quota exceeded"
- GPU quota təsdiqi gözləyin (2-4 saat)
- CPU versiyası ilə test edin (GPU_FLAG="" deploy.sh-də)

### "Model download timeout"
```bash
# Timeout artırın
gcloud run deploy gpu-analyzer --timeout=600
```

### "VirusTotal rate limit"
- 15 saniyə gözləyin
- Və ya mock response istifadə edin (test üçün)

---

## 📞 Kömək Lazımdırsa

1. **SETUP_INSTRUCTIONS.md** - Ətraflı təlimat
2. **README.md** - Tam dokumentasiya
3. GitHub Issues - Problem bildir
4. Hackathon Discord - Canlı dəstək

---

## ✅ Son Checklist

Submission öncəsi yoxlayın:

- [ ] API-lər işləyir (`./test_api.sh`)
- [ ] Backend deployed və healthy
- [ ] GPU service deployed (və ya CPU fallback)
- [ ] Test samples işləyir
- [ ] README.md tam
- [ ] Demo video hazır (3 dəqiqə)
- [ ] Architecture diagram var
- [ ] GitHub repo public
- [ ] DevPost submission doldurulub

---

**🚀 Uğurlar Hackathon-da!**

*P.S. Sualınız varsa - soruşun! Biz buradayıq.* 🛡️
