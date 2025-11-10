#!/bin/bash

# ShadowHunter AI - Local Development Startup Script
# This script starts both backend and frontend for local development

set -e  # Exit on error

echo "🛡️  ShadowHunter AI - Local Development Setup"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0;0m' # No Color

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 not found!${NC}"
    echo "Install Python 3.9+ from https://www.python.org/"
    exit 1
fi

echo -e "${GREEN}✓${NC} Python found: $(python3 --version)"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js not found!${NC}"
    echo "Install Node.js from https://nodejs.org/"
    exit 1
fi

echo -e "${GREEN}✓${NC} Node.js found: $(node --version)"
echo ""

# Backend Setup
echo "📦 Setting up Backend..."
cd backend

if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Analyzer dependencies
echo "Installing analyzer dependencies..."
pip install -q -r ../analyzer/requirements.txt

echo -e "${GREEN}✓${NC} Backend setup complete"
echo ""

# Check for .env
if [ ! -f "../.env" ]; then
    echo -e "${YELLOW}⚠️  No .env file found!${NC}"
    echo "Creating from .env.example..."
    cp ../.env.example ../.env
    echo -e "${YELLOW}➡️  Please edit .env and add your API keys${NC}"
    echo ""
fi

# Frontend Setup
echo "🎨 Setting up Frontend..."
cd ../frontend

if [ ! -d "node_modules" ]; then
    echo "Installing npm packages..."
    npm install
else
    echo -e "${GREEN}✓${NC} npm packages already installed"
fi

echo -e "${GREEN}✓${NC} Frontend setup complete"
echo ""

# Start Services
echo "🚀 Starting Services..."
echo "================================================"
echo ""

# Kill existing processes
killall -9 python3 2>/dev/null || true
killall -9 node 2>/dev/null || true

echo "Starting Backend (http://localhost:8080)..."
cd ../backend
source venv/bin/activate
python3 main.py > ../logs/backend.log 2>&1 &
BACKEND_PID=$!

sleep 3

echo "Starting Frontend (http://localhost:3000)..."
cd ../frontend
npm run dev > ../logs/frontend.log 2>&1 &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}✅ ShadowHunter AI is running!${NC}"
echo "================================================"
echo ""
echo "📡 Backend API:  http://localhost:8080"
echo "🎨 Frontend UI:  http://localhost:3000"
echo "📚 API Docs:     http://localhost:8080/docs"
echo ""
echo "📋 Process IDs:"
echo "   Backend:  $BACKEND_PID"
echo "   Frontend: $FRONTEND_PID"
echo ""
echo "📝 Logs:"
echo "   Backend:  tail -f logs/backend.log"
echo "   Frontend: tail -f logs/frontend.log"
echo ""
echo "⏹️  To stop: kill $BACKEND_PID $FRONTEND_PID"
echo "   Or press Ctrl+C and run: killall -9 python3 node"
echo ""

# Wait
wait
