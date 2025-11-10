# 🛡️ ShadowHunter AI - Setup Instructions

## 📋 LAZIM OLAN HESABLAR VƏ API-LAR

### 1️⃣ Google Cloud Platform (ƏN VACİB!)

**Nə etməlisiniz:**

1. **Google Cloud hesabı yaradın:**
   - https://console.cloud.google.com/
   - Kredit kartı lazımdır (amma $300 pulsuz kredit verilir)

2. **Cloud Run Hackathon kreditini tələb edin:**
   - https://run.devpost.com/resources
   - "Request GPU Access" düyməsinə basın
   - Formda qeyd edin: "ShadowHunter AI - AI-Generated Malware Detection Platform"
   - **ÇOX VACİB:** GPU quota təsdiqi 2-4 saat çəkir - DƏRHAL edin!

3. **gcloud CLI quraşdırın:**
   ```bash
   # Linux/Mac:
   curl https://sdk.cloud.google.com | bash
   exec -l $SHELL

   # Və ya:
   # https://cloud.google.com/sdk/docs/install
   ```

4. **Autentifikasiya:**
   ```bash
   gcloud auth login
   gcloud auth application-default login
   ```

---

### 2️⃣ VirusTotal API Key (PULSUZ)

**Nə etməlisiniz:**

1. https://www.virustotal.com/ səhifəsinə gedin
2. "Sign Up" ilə hesab yaradın (Gmail ilə giriş olar)
3. Yuxarı sağ küncdə profil → "API Key"
4. API açarını kopyalayın

**Rate Limits:**
- Pulsuz: 4 request / dəqiqə
- Bu demo üçün kifayətdir

**API Key formatı:**
```
your_virustotal_api_key_here_64_characters_long
```

---

### 3️⃣ Google Gemini API Key (PULSUZ)

**Nə etməlisiniz:**

1. https://makersuite.google.com/ səhifəsinə gedin
2. "Get API Key" düyməsinə basın
3. "Create API key in new project" seçin
4. API açarını kopyalayın

**Alternativ:**
- Google AI Studio: https://aistudio.google.com/app/apikey

**Rate Limits:**
- Pulsuz: 15 requests / dəqiqə
- Bu demo üçün kifayətdir

---

## 🚀 QURAŞDIRMA ADDIMARI

### Addım 1: Proyekti klonlayın (və ya mövcud direktoriyadasınız)

```bash
cd /home/kali/Desktop/ShadowHunterAI
```

### Addım 2: .env faylını yaradın

```bash
cp .env.example .env
nano .env  # və ya istənilən editor
```

### Addım 3: .env faylını doldurun

**.env faylı:**
```bash
# Google Cloud Configuration
PROJECT_ID=shadowhunter-ai-2025    # İstədiyiniz ad (unikal olmalıdır)
REGION=europe-west4                 # GPU üçün ən yaxşı region

# Storage
STORAGE_BUCKET=shadowhunter-samples-YOUR_UNIQUE_ID
RESULTS_BUCKET=shadowhunter-results-YOUR_UNIQUE_ID

# API Keys (BURAYA ÖZ AÇARLARINIZI QOYUN!)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# Service URLs (deployment-dən sonra doldurulacaq)
GPU_SERVICE_URL=https://gpu-analyzer-xxxxxxxx-ew.a.run.app
BACKEND_SERVICE_URL=https://backend-api-xxxxxxxx-ew.a.run.app

# Firebase
GOOGLE_APPLICATION_CREDENTIALS=./service-account-key.json
```

### Addım 4: Google Cloud infrastrukturunu quraşdırın

```bash
# Setup skriptini işə salın
chmod +x setup.sh
./setup.sh
```

Bu skript:
- ✅ Google Cloud layihəsini yaradacaq
- ✅ Lazımi API-ları aktivləşdirəcək
- ✅ Cloud Storage bucket-lərini yaradacaq
- ✅ Firestore database yaradacaq
- ✅ Service account yaradıb açarını endirecək

### Addım 5: GPU Quota-nın təsdiqini gözləyin

⏳ **Bu ƏN VACİB ADDIMDIR!**

GPU quota tələbiniz təsdiq olunana qədər (2-4 saat):
1. https://run.devpost.com/resources səhifəsindən status yoxlayın
2. Emailinizi yoxlayın
3. Bu müddətdə CPU versiyası ilə test edə bilərsiniz

---

## 🧪 LOKAL TEST (GPU olmadan)

GPU quota gözləyərkən local test edə bilərsiniz:

### Backend API test:

```bash
cd backend
pip install -r requirements.txt

# .env faylını oxumaq üçün
export $(cat ../.env | xargs)

# API-ni işə salın
python main.py
```

Test: http://localhost:8080/health

### Pattern Detector test:

```bash
cd analyzer
python patterns.py
```

---

## 📦 DEPLOYMENT (GPU quota təsdiq olunandan sonra)

### 1. Backend API deploy:

```bash
cd backend
gcloud builds submit --tag gcr.io/$PROJECT_ID/backend-api
gcloud run deploy backend-api \
  --image gcr.io/$PROJECT_ID/backend-api \
  --platform managed \
  --region $REGION \
  --memory 8Gi \
  --cpu 4 \
  --timeout 300 \
  --allow-unauthenticated
```

URL-i kopyalayın və `.env` faylında `BACKEND_SERVICE_URL` olaraq qeyd edin.

### 2. GPU Service deploy:

```bash
cd gpu-service
gcloud builds submit --tag gcr.io/$PROJECT_ID/gpu-analyzer
gcloud run deploy gpu-analyzer \
  --image gcr.io/$PROJECT_ID/gpu-analyzer \
  --platform managed \
  --region $REGION \
  --memory 16Gi \
  --cpu 4 \
  --timeout 300 \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --max-instances 3 \
  --min-instances 0 \
  --allow-unauthenticated
```

URL-i kopyalayın və `.env` faylında `GPU_SERVICE_URL` olaraq qeyd edin.

---

## 🔍 TROUBLESHOOTİNG

### Problem: "GPU quota exceeded"
**Həll:** GPU quota tələbiniz hələ təsdiq olunmayıb.
- https://run.devpost.com/resources səhifəsindən yenidən tələb edin
- Support ilə əlaqə saxlayın

### Problem: "VirusTotal API error 403"
**Həll:** API key səhvdir və ya rate limit.
- API key-i yoxlayın
- 15 saniyə gözləyin (rate limit)

### Problem: "Model download failed"
**Həll:** Gemma 2 modelinin endirilməsi çox vaxt alır (18GB).
- İlk request 2-3 dəqiqə çəkə bilər
- Logs-a baxın: `gcloud run logs read gpu-analyzer`

### Problem: "Permission denied"
**Həll:** Service account icazələri.
```bash
# Service account-a rollar verin:
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:shadowhunter-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.admin"
```

---

## ✅ HAZIR OLDUĞUNUZDAN ƏMİN OLMAQ

Test checklist:

```bash
# 1. Backend health check
curl https://YOUR_BACKEND_URL/health

# 2. GPU service health check
curl https://YOUR_GPU_URL/health

# 3. Test analysis (test faylı ilə)
curl -X POST https://YOUR_BACKEND_URL/api/analyze \
  -F "file=@tests/samples/test_sample.py"
```

Əgər hər üç test işləyirsə - **hazırsınız!** 🎉

---

## 📞 YARDIM

- Google Cloud support: https://cloud.google.com/support
- Hackathon Discord: https://run.devpost.com/ (Join Discord düyməsi)
- Layihə issues: GitHub issues tab

---

**Uğurlar! 🚀**
