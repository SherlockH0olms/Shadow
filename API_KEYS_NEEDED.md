# 🔑 ShadowHunter AI - Lazım Olan API Açarları

## 📋 TƏCİLİ: Bu Açarları İNDİ Əldə Edin!

---

## 1️⃣ Google Cloud Platform (VACİB!)

### Nə Lazımdır:
- Google Cloud hesabı
- Kredit kartı (amma $300 pulsuz kredit verilir)
- GPU quota (hackathon üçün pulsuz tələb edilir)

### Necə Əldə Edilir:

**A) Google Cloud Hesabı:**
```
1. https://console.cloud.google.com/ açın
2. "Get started for free" düyməsinə basın
3. Kredit kartı məlumatlarını daxil edin ($300 pulsuz kredit alacaqsınız)
4. Hesab yaradın
```

**B) gcloud CLI Quraşdırın:**
```bash
# Linux/Kali:
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# Autentifikasiya:
gcloud auth login
gcloud auth application-default login
```

**C) GPU Quota Tələb Edin (ƏN VACİB!):**
```
⚠️  BU ADDIM TƏCİLİDİR - 2-4 SAAT ÇƏKƏ BİLƏR!

1. https://run.devpost.com/resources açın
2. "Request GPU Access" düyməsinə basın
3. Formu doldurun:
   - Project Name: ShadowHunter AI
   - Description: "AI-Generated Malware Detection Platform using
     Gemma 2 9B model on Cloud Run with L4 GPU for real-time analysis"
   - GPU Type: NVIDIA L4
   - Region: europe-west4

4. Submit edin
5. Email gözləyin (2-4 saat)

⏰ Bu müddətdə digər işlərə başlaya bilərsiniz!
```

**Nə üçün lazımdır:**
- Cloud Run serverless deployment
- L4 GPU malware analysis
- Cloud Storage fayl saxlama
- Firestore database

---

## 2️⃣ VirusTotal API Key (PULSUZ!)

### Nə Lazımdır:
- VirusTotal hesabı (pulsuz)
- API key (4 request/dəqiqə pulsuz)

### Necə Əldə Edilir:

```
1. https://www.virustotal.com/ açın
2. Sağ yuxarı küncdə "Sign Up" basın
3. Email və ya Gmail ilə qeydiyyatdan keçin
4. Email-i təsdiq edin
5. Profil ikonuna basın → "API Key"
6. API açarını kopyalayın
```

**API Key formatı:**
```
64 simvolluq string:
abc123def456...xyz789
```

**Rate Limits:**
- Pulsuz: 4 requests / dəqiqə
- Pulsuz: 500 requests / gün
- Premium: 1000 requests / gün (əgər lazımsa)

**Nə üçün lazımdır:**
- Traditional AV ilə müqayisə
- Demo üçün "ShadowHunter vs VirusTotal" göstərmək
- Proof of concept

---

## 3️⃣ Google Gemini API Key (PULSUZ, Opsional)

### Nə Lazımdır:
- Google hesabı
- Gemini API key

### Necə Əldə Edilir:

```
Variant 1 - Google AI Studio:
1. https://aistudio.google.com/app/apikey açın
2. "Get API key" düyməsinə basın
3. "Create API key in new project" seçin
4. API key kopyalayın

Variant 2 - Google MakerSuite:
1. https://makersuite.google.com/ açın
2. "Get API Key" düyməsinə basın
3. API key kopyalayın
```

**API Key formatı:**
```
AIzaSy...
```

**Rate Limits:**
- Pulsuz: 15 requests / dəqiqə
- Pulsuz: 1500 requests / gün

**Qeyd:** Bu opsionaldır. Gemma 2 modeli Cloud Run GPU-da lokal işləyəcək.

---

## 📝 .env Faylını Doldurun

API açarlarınızı əldə etdikdən sonra:

```bash
cd /home/kali/Desktop/ShadowHunterAI
cp .env.example .env
nano .env
```

**.env faylında düzəlişlər:**
```bash
# Google Cloud
PROJECT_ID=shadowhunter-ai-YOUR-NAME-2025    # Unikal ad seçin!
REGION=europe-west4

# Storage (bucket names unikal olmalıdır!)
STORAGE_BUCKET=shadowhunter-samples-123456
RESULTS_BUCKET=shadowhunter-results-123456

# API Keys (BURAYA ÖZ AÇARLARINIZI QOYUN!)
VIRUSTOTAL_API_KEY=buraya_virustotal_açarınızı_yapışdırın
GEMINI_API_KEY=buraya_gemini_açarınızı_yapışdırın

# Service URLs (deployment-dən SONRA doldurulacaq)
GPU_SERVICE_URL=
BACKEND_SERVICE_URL=

# Firebase
GOOGLE_APPLICATION_CREDENTIALS=./service-account-key.json
```

---

## ✅ Yoxlama Checklist

Hər şeyi əldə etdiyinizdən əmin olun:

- [ ] Google Cloud hesabı yaradılıb
- [ ] gcloud CLI quraşdırılıb və autentifikasiya edilib
- [ ] GPU quota tələb edilib (və ya təsdiq gözlənilir)
- [ ] VirusTotal API key alınıb
- [ ] Gemini API key alınıb (opsional)
- [ ] .env faylı yaradılıb və doldurulub
- [ ] Bucket names unikal edilib

---

## 🚀 Növbəti Addımlar

API açarlarınız hazırdırsa:

```bash
# 1. İnfrastrukturu qurun
./setup.sh

# 2. Lokal test edin
cd analyzer && python3 patterns.py

# 3. GPU quota təsdiqi gəldikdə - deploy edin
./deploy.sh

# 4. Test edin
./test_api.sh
```

---

## 🆘 Kömək Lazımdırsa

### Problem: "GPU quota denied"
**Həll:** Hackathon support ilə əlaqə:
- https://run.devpost.com/ Discord
- Formda daha ətraflı izah verin
- "Cloud Run Hackathon 2025" qeyd edin

### Problem: "VirusTotal 403 Forbidden"
**Həll:**
- API key-i yenidən kopyalayın (boşluq olmamalıdır)
- Rate limit gözləyin (15 saniyə)
- Yeni hesab yaradın

### Problem: "Google Cloud billing required"
**Həll:**
- Kredit kartı əlavə etməlisiniz (charge olunmaz)
- $300 pulsuz kredit alacaqsınız
- Hackathon üçün kifayətdir

---

## 💰 Xərc Təxmini

**Tam Hackathon (48 saat):**
- GPU istifadəsi: ~$50-80
- Storage: ~$1
- Networking: ~$2
- **CƏMI: ~$60-100**

**Google Cloud pulsuz $300 kredit ilə ödənilir!**

---

**Uğurlar! 🚀**
