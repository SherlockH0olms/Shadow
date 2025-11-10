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
echo "3) Ghidra Service only (NEW!)"
echo "4) Backend + GPU"
echo "5) All services (Backend + GPU + Ghidra)"
read -p "Select (1-5): " choice

deploy_backend=false
deploy_gpu=false
deploy_ghidra=false

case $choice in
    1) deploy_backend=true ;;
    2) deploy_gpu=true ;;
    3) deploy_ghidra=true ;;
    4) deploy_backend=true; deploy_gpu=true ;;
    5) deploy_backend=true; deploy_gpu=true; deploy_ghidra=true ;;
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
        --set-env-vars="PROJECT_ID=${PROJECT_ID},STORAGE_BUCKET=${STORAGE_BUCKET},GPU_SERVICE_URL=${GPU_SERVICE_URL},GHIDRA_SERVICE_URL=${GHIDRA_SERVICE_URL}"

    # Get service URL
    BACKEND_URL=$(gcloud run services describe backend-api --region=${REGION} --format='value(status.url)')
    echo ""
    echo "✅ Backend API deployed!"
    echo "   URL: $BACKEND_URL"

    cd ..
fi

# Deploy GPU Service
if [ "$deploy_gpu" = true ]; then
    echo ""
    echo "🚀 Deploying GPU Analysis Service..."
    echo "====================================="

    # Check GPU quota
    read -p "Have you received GPU quota approval? (y/n): " gpu_approved

    if [ "$gpu_approved" != "y" ]; then
        echo "⚠️  Warning: GPU quota needed!"
        echo "   Visit: https://run.devpost.com/resources"
        read -p "Deploy CPU-only? (y/n): " use_cpu
        if [ "$use_cpu" != "y" ]; then
            echo "Skipping GPU service."
        else
            GPU_FLAG=""
            GPU_TYPE_FLAG=""
            MEMORY="16Gi"
        fi
    else
        GPU_FLAG="--gpu 1"
        GPU_TYPE_FLAG="--gpu-type nvidia-l4"
        MEMORY="24Gi"
    fi

    cd gpu-service

    echo "Building GPU service..."
    gcloud builds submit --tag gcr.io/${PROJECT_ID}/gpu-analyzer --timeout=20m

    echo "Deploying to Cloud Run..."
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
        --allow-unauthenticated \
        --set-env-vars="USE_GPU=true,GHIDRA_SERVICE_URL=${GHIDRA_SERVICE_URL}"

    GPU_URL=$(gcloud run services describe gpu-analyzer --region=${REGION} --format='value(status.url)')
    echo ""
    echo "✅ GPU Service deployed!"
    echo "   URL: $GPU_URL"

    cd ..
fi

# Deploy Ghidra Service (NEW!)
if [ "$deploy_ghidra" = true ]; then
    echo ""
    echo "🚀 Deploying Ghidra Binary Analysis Service..."
    echo "==============================================="

    cd ghidra-service

    echo "Building Ghidra service (this may take 10-15 minutes - Ghidra is 2GB+)..."
    gcloud builds submit --tag gcr.io/${PROJECT_ID}/ghidra-service --timeout=30m

    echo "Deploying to Cloud Run..."
    gcloud run deploy ghidra-service \
        --image gcr.io/${PROJECT_ID}/ghidra-service \
        --platform managed \
        --region ${REGION} \
        --memory 8Gi \
        --cpu 4 \
        --timeout 300 \
        --max-instances 5 \
        --allow-unauthenticated

    GHIDRA_URL=$(gcloud run services describe ghidra-service --region=${REGION} --format='value(status.url)')
    echo ""
    echo "✅ Ghidra Service deployed!"
    echo "   URL: $GHIDRA_URL"
    echo ""
    echo "⚠️  Update .env file with:"
    echo "   GHIDRA_SERVICE_URL=$GHIDRA_URL"

    cd ..
fi

echo ""
echo "🎉 Deployment Complete!"
echo "======================="
echo ""
echo "📝 Service URLs:"
[ "$deploy_backend" = true ] && echo "   Backend:  $BACKEND_URL"
[ "$deploy_gpu" = true ] && echo "   GPU:      $GPU_URL"
[ "$deploy_ghidra" = true ] && echo "   Ghidra:   $GHIDRA_URL"
echo ""
echo "📝 Next Steps:"
echo "   1. Update .env with service URLs"
echo "   2. Test endpoints:"
[ "$deploy_backend" = true ] && echo "      curl $BACKEND_URL/health"
[ "$deploy_gpu" = true ] && echo "      curl $GPU_URL/health"
[ "$deploy_ghidra" = true ] && echo "      curl $GHIDRA_URL/health"
echo ""
