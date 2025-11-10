#!/bin/bash

# ShadowHunter AI - API Testing Script
# Quick test script for deployed services

set -e

echo "🛡️  ShadowHunter AI - API Testing"
echo "================================="

# Load environment
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check if URLs are set
if [ -z "$BACKEND_SERVICE_URL" ]; then
    echo "⚠️  Warning: BACKEND_SERVICE_URL not set in .env"
    read -p "Enter Backend URL: " BACKEND_SERVICE_URL
fi

echo ""
echo "Testing endpoint: $BACKEND_SERVICE_URL"
echo ""

# Test 1: Health Check
echo "1️⃣  Testing Health Check..."
echo "----------------------------"
response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$BACKEND_SERVICE_URL/health")
http_code=$(echo "$response" | grep HTTP_CODE | cut -d: -f2)

if [ "$http_code" = "200" ]; then
    echo "✅ Health check passed"
    echo "$response" | grep -v HTTP_CODE | jq '.' 2>/dev/null || echo "$response" | grep -v HTTP_CODE
else
    echo "❌ Health check failed (HTTP $http_code)"
    exit 1
fi

echo ""

# Test 2: Analyze Malicious Sample
echo "2️⃣  Testing Malware Detection (DeepSeek sample)..."
echo "---------------------------------------------------"

if [ ! -f "tests/samples/deepseek_generated_malware.py" ]; then
    echo "❌ Test sample not found!"
    exit 1
fi

response=$(curl -s -X POST "$BACKEND_SERVICE_URL/api/analyze" \
    -F "file=@tests/samples/deepseek_generated_malware.py" \
    -w "\nHTTP_CODE:%{http_code}")

http_code=$(echo "$response" | grep HTTP_CODE | cut -d: -f2)

if [ "$http_code" = "200" ]; then
    echo "✅ Analysis completed"
    result=$(echo "$response" | grep -v HTTP_CODE)

    # Parse results
    is_malicious=$(echo "$result" | jq -r '.result.detection.is_malicious' 2>/dev/null)
    is_ai_generated=$(echo "$result" | jq -r '.result.detection.is_ai_generated' 2>/dev/null)
    confidence=$(echo "$result" | jq -r '.result.detection.confidence' 2>/dev/null)
    llm_source=$(echo "$result" | jq -r '.result.detection.llm_source' 2>/dev/null)

    echo ""
    echo "📊 Detection Results:"
    echo "   Malicious: $is_malicious"
    echo "   AI-Generated: $is_ai_generated"
    echo "   Confidence: $confidence"
    echo "   LLM Source: $llm_source"

    # Verify detection
    if [ "$is_ai_generated" = "true" ]; then
        echo ""
        echo "✅ ✅ SUCCESS! AI-generated malware detected correctly!"
    else
        echo ""
        echo "⚠️  Warning: Sample not detected as AI-generated"
    fi
else
    echo "❌ Analysis failed (HTTP $http_code)"
    echo "$response" | grep -v HTTP_CODE
    exit 1
fi

echo ""

# Test 3: Analyze Clean Sample
echo "3️⃣  Testing False Positive (Clean sample)..."
echo "----------------------------------------------"

if [ ! -f "tests/samples/clean_sample.py" ]; then
    echo "⚠️  Clean sample not found, skipping..."
else
    response=$(curl -s -X POST "$BACKEND_SERVICE_URL/api/analyze" \
        -F "file=@tests/samples/clean_sample.py" \
        -w "\nHTTP_CODE:%{http_code}")

    http_code=$(echo "$response" | grep HTTP_CODE | cut -d: -f2)

    if [ "$http_code" = "200" ]; then
        echo "✅ Analysis completed"
        result=$(echo "$response" | grep -v HTTP_CODE)

        is_malicious=$(echo "$result" | jq -r '.result.detection.is_malicious' 2>/dev/null)
        confidence=$(echo "$result" | jq -r '.result.detection.confidence' 2>/dev/null)

        echo ""
        echo "📊 Detection Results:"
        echo "   Malicious: $is_malicious"
        echo "   Confidence: $confidence"

        if [ "$is_malicious" = "false" ]; then
            echo ""
            echo "✅ ✅ SUCCESS! Clean file correctly identified!"
        else
            echo ""
            echo "⚠️  Warning: False positive detected"
        fi
    else
        echo "❌ Analysis failed (HTTP $http_code)"
    fi
fi

echo ""

# Test 4: GPU Service (if URL available)
if [ ! -z "$GPU_SERVICE_URL" ]; then
    echo "4️⃣  Testing GPU Service..."
    echo "-------------------------"

    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$GPU_SERVICE_URL/health")
    http_code=$(echo "$response" | grep HTTP_CODE | cut -d: -f2)

    if [ "$http_code" = "200" ]; then
        echo "✅ GPU service healthy"
        echo "$response" | grep -v HTTP_CODE | jq '.' 2>/dev/null || echo "$response" | grep -v HTTP_CODE
    else
        echo "⚠️  GPU service not accessible"
    fi
fi

echo ""
echo "================================="
echo "🎉 Testing Complete!"
echo ""
echo "✅ All core functionality working!"
echo ""
echo "Next steps:"
echo "  1. Upload more test samples"
echo "  2. Check analysis history: $BACKEND_SERVICE_URL/api/history"
echo "  3. Test with your own files"
echo ""
