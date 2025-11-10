#!/bin/bash

# ShadowHunter AI - Deployment Script
# Deploys all services to Google Cloud Run

set -e

echo "🛡️  ShadowHunter AI - Deployment"
echo "================================"

# Load environment variables
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo "Please copy .env.example to .env and configure it."
    exit 1
fi

export $(cat .env | grep -v '^#' | xargs)

# Check required variables
if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: PROJECT_ID not set in .env"
    exit 1
fi

if [ -z "$REGION" ]; then
    echo "❌ Error: REGION not set in .env"
    exit 1
fi

echo "📋 Deployment Configuration:"
echo "   Project ID: $PROJECT_ID"
echo "   Region: $REGION"
echo ""

# Set gcloud project
gcloud config set project $PROJECT_ID

# Ask which services to deploy
echo "Which services do you want to deploy?"
echo "1) Backend API only"
echo "2) GPU Service only"
echo "3) Both services"
read -p "Select (1-3): " choice

deploy_backend=false
deploy_gpu=false

case $choice in
    1) deploy_backend=true ;;
    2) deploy_gpu=true ;;
    3) deploy_backend=true; deploy_gpu=true ;;
    *) echo "Invalid choice"; exit 1 ;;
esac

# Deploy Backend API
if [ "$deploy_backend" = true ]; then
    echo ""
    echo "🚀 Deploying Backend API..."
    echo "============================"

    cd backend

    # Build container
    echo "Building container..."
    gcloud builds submit --tag gcr.io/${PROJECT_ID}/backend-api

    # Deploy to Cloud Run
    echo "Deploying to Cloud Run..."
    gcloud run deploy backend-api \
        --image gcr.io/${PROJECT_ID}/backend-api \
        --platform managed \
        --region ${REGION} \
        --memory 8Gi \
        --cpu 4 \
        --timeout 300 \
        --max-instances 10 \
        --allow-unauthenticated \
        --set-env-vars="PROJECT_ID=${PROJECT_ID},STORAGE_BUCKET=${STORAGE_BUCKET},RESULTS_BUCKET=${RESULTS_BUCKET},GPU_SERVICE_URL=${GPU_SERVICE_URL}"

    # Get service URL
    BACKEND_URL=$(gcloud run services describe backend-api --region=${REGION} --format='value(status.url)')
    echo ""
    echo "✅ Backend API deployed successfully!"
    echo "   URL: $BACKEND_URL"
    echo ""
    echo "⚠️  Update .env file with:"
    echo "   BACKEND_SERVICE_URL=$BACKEND_URL"

    cd ..
fi

# Deploy GPU Service
if [ "$deploy_gpu" = true ]; then
    echo ""
    echo "🚀 Deploying GPU Analysis Service..."
    echo "====================================="

    # Check if GPU quota is available
    read -p "Have you received GPU quota approval? (y/n): " gpu_approved

    if [ "$gpu_approved" != "y" ]; then
        echo "⚠️  Warning: You need GPU quota approval first!"
        echo "   Visit: https://run.devpost.com/resources"
        echo ""
        read -p "Deploy without GPU (CPU-only, slower)? (y/n): " use_cpu

        if [ "$use_cpu" != "y" ]; then
            echo "Skipping GPU service deployment."
            exit 0
        fi

        GPU_FLAG=""
        GPU_TYPE_FLAG=""
        MEMORY="16Gi"
    else
        GPU_FLAG="--gpu 1"
        GPU_TYPE_FLAG="--gpu-type nvidia-l4"
        MEMORY="24Gi"
    fi

    cd gpu-service

    # Copy required modules
    echo "Preparing deployment package..."
    cp -r ../analyzer ./ 2>/dev/null || true
    cp -r ../integrations ./ 2>/dev/null || true
    cp ../service-account-key.json ./ 2>/dev/null || true

    # Build container
    echo "Building GPU service container (this may take 5-10 minutes)..."
    gcloud builds submit --tag gcr.io/${PROJECT_ID}/gpu-analyzer --timeout=20m

    # Deploy to Cloud Run with GPU
    echo "Deploying to Cloud Run with GPU..."
    gcloud run deploy gpu-analyzer \
        --image gcr.io/${PROJECT_ID}/gpu-analyzer \
        --platform managed \
        --region ${REGION} \
        --memory ${MEMORY} \
        --cpu 4 \
        --timeout 300 \
        ${GPU_FLAG} \
        ${GPU_TYPE_FLAG} \
        --max-instances 3 \
        --min-instances 0 \
        --allow-unauthenticated \
        --set-env-vars="PROJECT_ID=${PROJECT_ID},STORAGE_BUCKET=${STORAGE_BUCKET},VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY},USE_GPU=true"

    # Clean up copied files
    rm -rf analyzer integrations service-account-key.json 2>/dev/null || true

    # Get service URL
    GPU_URL=$(gcloud run services describe gpu-analyzer --region=${REGION} --format='value(status.url)')
    echo ""
    echo "✅ GPU Service deployed successfully!"
    echo "   URL: $GPU_URL"
    echo ""
    echo "⚠️  Update .env file with:"
    echo "   GPU_SERVICE_URL=$GPU_URL"

    cd ..
fi

echo ""
echo "🎉 Deployment Complete!"
echo "======================="
echo ""
echo "📝 Next Steps:"
echo "   1. Update .env file with service URLs shown above"
echo "   2. Test the API:"
if [ "$deploy_backend" = true ]; then
    echo "      curl ${BACKEND_URL}/health"
fi
if [ "$deploy_gpu" = true ]; then
    echo "      curl ${GPU_URL}/health"
fi
echo ""
echo "   3. Try uploading a test file through the API"
echo ""
