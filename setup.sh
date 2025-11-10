#!/bin/bash

# ShadowHunter AI - Setup Script
# This script sets up Google Cloud infrastructure

set -e

echo "🛡️  ShadowHunter AI - Infrastructure Setup"
echo "=========================================="

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "⚠️  Warning: .env file not found. Using .env.example as template."
    cp .env.example .env
    echo "Please edit .env file with your API keys and run again."
    exit 1
fi

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ gcloud CLI not found. Please install: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

echo ""
echo "📋 Project Configuration:"
echo "   Project ID: $PROJECT_ID"
echo "   Region: $REGION"
echo ""

# 1. Create Google Cloud Project
echo "1️⃣  Creating Google Cloud Project..."
gcloud projects create $PROJECT_ID --name="ShadowHunter AI" 2>/dev/null || echo "   Project already exists"
gcloud config set project $PROJECT_ID

# 2. Enable required APIs
echo ""
echo "2️⃣  Enabling Google Cloud APIs..."
gcloud services enable \
    run.googleapis.com \
    storage.googleapis.com \
    firestore.googleapis.com \
    cloudbuild.googleapis.com \
    aiplatform.googleapis.com \
    artifactregistry.googleapis.com

# 3. Create Cloud Storage Buckets
echo ""
echo "3️⃣  Creating Cloud Storage Buckets..."
gsutil mb -l $REGION gs://$STORAGE_BUCKET 2>/dev/null || echo "   Samples bucket already exists"
gsutil mb -l $REGION gs://$RESULTS_BUCKET 2>/dev/null || echo "   Results bucket already exists"

# Set bucket permissions (public read for demo - adjust for production)
gsutil iam ch allUsers:objectViewer gs://$RESULTS_BUCKET 2>/dev/null || true

# 4. Create Firestore Database
echo ""
echo "4️⃣  Creating Firestore Database..."
gcloud firestore databases create --location=$REGION 2>/dev/null || echo "   Firestore already exists"

# 5. Create Artifact Registry
echo ""
echo "5️⃣  Creating Artifact Registry..."
gcloud artifacts repositories create shadowhunter-repo \
    --repository-format=docker \
    --location=$REGION \
    --description="ShadowHunter AI container images" 2>/dev/null || echo "   Repository already exists"

# 6. GPU Quota Request Instructions
echo ""
echo "⚠️  IMPORTANT: GPU QUOTA REQUEST REQUIRED!"
echo "=========================================="
echo ""
echo "You MUST request L4 GPU quota for Cloud Run:"
echo ""
echo "1. Visit: https://run.devpost.com/resources"
echo "2. Fill out the GPU access request form"
echo "3. Mention: 'ShadowHunter AI - AI-Generated Malware Detection'"
echo "4. Wait for approval (2-4 hours)"
echo ""
echo "⏳ DO NOT proceed with GPU deployment until quota is approved!"
echo ""

# 7. Create Service Account
echo "6️⃣  Creating Service Account..."
SERVICE_ACCOUNT="shadowhunter-sa@${PROJECT_ID}.iam.gserviceaccount.com"
gcloud iam service-accounts create shadowhunter-sa \
    --display-name="ShadowHunter AI Service Account" 2>/dev/null || echo "   Service account already exists"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/storage.admin" 2>/dev/null || true

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/datastore.user" 2>/dev/null || true

# Download service account key
echo "   Downloading service account key..."
gcloud iam service-accounts keys create service-account-key.json \
    --iam-account=$SERVICE_ACCOUNT 2>/dev/null || echo "   Key already exists"

echo ""
echo "✅ Infrastructure setup completed!"
echo ""
echo "📝 Next Steps:"
echo "   1. Edit .env file with your API keys:"
echo "      - VIRUSTOTAL_API_KEY (get from: https://www.virustotal.com)"
echo "      - GEMINI_API_KEY (get from: https://makersuite.google.com)"
echo ""
echo "   2. Request GPU quota (see instructions above)"
echo ""
echo "   3. Run: ./deploy.sh to deploy services"
echo ""
