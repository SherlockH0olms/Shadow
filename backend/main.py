#!/usr/bin/env python3
"""
ShadowHunter AI - Backend API Service
Main FastAPI application for file upload and analysis orchestration

Supports both local development and cloud deployment
"""

import os
import sys
import hashlib
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, List

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

# Add analyzer to path for local imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'analyzer'))

try:
    from patterns import AICodePatternDetector
    from yara_scanner import YaraScanner
    ANALYZER_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Analyzer modules not available: {e}")
    ANALYZER_AVAILABLE = False

# Optional Cloud imports
try:
    from google.cloud import storage, firestore
    CLOUD_AVAILABLE = True
except ImportError:
    CLOUD_AVAILABLE = False
    logging.warning("Google Cloud libraries not available - running in local mode")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="ShadowHunter AI API",
    description="AI-Generated Malware Detection Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Environment configuration
CLOUD_MODE = os.getenv("CLOUD_MODE", "false").lower() == "true"
GPU_SERVICE_URL = os.getenv("GPU_SERVICE_URL", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
LOCAL_STORAGE_PATH = Path(os.getenv("LOCAL_STORAGE_PATH", "./storage"))

# Create local storage directory
LOCAL_STORAGE_PATH.mkdir(parents=True, exist_ok=True)
(LOCAL_STORAGE_PATH / "uploads").mkdir(exist_ok=True)
(LOCAL_STORAGE_PATH / "results").mkdir(exist_ok=True)

# Initialize analyzers
pattern_detector = None
yara_scanner = None

if ANALYZER_AVAILABLE:
    try:
        pattern_detector = AICodePatternDetector()
        yara_scanner = YaraScanner()
        logger.info("✓ Pattern detector and YARA scanner initialized")
    except Exception as e:
        logger.error(f"Failed to initialize analyzers: {e}")

# Initialize Cloud clients (if available)
storage_client = None
db = None

if CLOUD_MODE and CLOUD_AVAILABLE:
    try:
        storage_client = storage.Client()
        db = firestore.Client()
        logger.info("✓ Google Cloud clients initialized")
    except Exception as e:
        logger.warning(f"Cloud clients initialization failed: {e}")
        CLOUD_MODE = False


# Models
class AnalysisResult(BaseModel):
    file_id: str
    file_name: str
    file_hash: str
    file_size: int
    status: str
    is_malicious: bool
    confidence: float
    risk_score: int
    llm_source: Optional[str] = None
    detected_patterns: List[str] = []
    evasion_techniques: List[str] = []
    malicious_indicators: List[str] = []
    yara_matches: List[Dict] = []
    created_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    mode: str
    analyzers: Dict[str, bool]
    cloud_services: Dict[str, bool]


@app.get("/", response_model=Dict)
async def root():
    """Root endpoint - API information."""
    return {
        "service": "ShadowHunter AI Backend",
        "status": "healthy",
        "version": "1.0.0",
        "mode": "cloud" if CLOUD_MODE else "local",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthResponse)
async def health():
    """Comprehensive health check."""
    health_status = {
        "status": "healthy",
        "version": "1.0.0",
        "mode": "cloud" if CLOUD_MODE else "local",
        "analyzers": {
            "pattern_detector": pattern_detector is not None,
            "yara_scanner": yara_scanner is not None and yara_scanner.is_enabled()
        },
        "cloud_services": {
            "storage": storage_client is not None,
            "firestore": db is not None,
            "gpu_service": bool(GPU_SERVICE_URL)
        }
    }

    # Test cloud connectivity if enabled
    if CLOUD_MODE:
        try:
            if storage_client:
                # Quick connectivity test
                list(storage_client.list_buckets(max_results=1))
                health_status["cloud_services"]["storage"] = True
        except Exception as e:
            logger.warning(f"Cloud storage check failed: {e}")
            health_status["cloud_services"]["storage"] = False

    return health_status


@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None
):
    """
    Main endpoint for malware analysis.

    Supports:
    - Python files (.py)
    - PowerShell scripts (.ps1)
    - JavaScript files (.js)
    - Binary files (.exe, .dll)

    Returns:
        Comprehensive analysis results
    """
    file_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat()

    try:
        # Read and validate file
        content = await file.read()
        file_size = len(content)
        file_hash = hashlib.sha256(content).hexdigest()

        logger.info(f"Analyzing file: {file.filename} (ID: {file_id})")

        # Size validation (max 10MB)
        max_size = 10 * 1024 * 1024
        if file_size > max_size:
            raise HTTPException(
                status_code=400,
                detail=f"File too large. Maximum: 10MB, Got: {file_size/1024/1024:.2f}MB"
            )

        # Store file locally
        upload_path = LOCAL_STORAGE_PATH / "uploads" / f"{file_id}_{file.filename}"
        with open(upload_path, 'wb') as f:
            f.write(content)

        # Perform analysis
        analysis_result = await _analyze_content(content, file.filename, file_hash)

        # Build response
        result = AnalysisResult(
            file_id=file_id,
            file_name=file.filename,
            file_hash=file_hash,
            file_size=file_size,
            status="completed",
            is_malicious=analysis_result.get("is_malicious", False),
            confidence=analysis_result.get("confidence", 0.0),
            risk_score=analysis_result.get("risk_score", 0),
            llm_source=analysis_result.get("llm_source"),
            detected_patterns=analysis_result.get("detected_patterns", []),
            evasion_techniques=analysis_result.get("evasion_techniques", []),
            malicious_indicators=analysis_result.get("malicious_indicators", []),
            yara_matches=analysis_result.get("yara_matches", []),
            created_at=created_at,
            completed_at=datetime.utcnow().isoformat()
        )

        # Save result locally
        result_path = LOCAL_STORAGE_PATH / "results" / f"{file_id}.json"
        with open(result_path, 'w') as f:
            f.write(result.json())

        # If cloud mode, also save to Firestore
        if CLOUD_MODE and db:
            try:
                db.collection('analyses').document(file_id).set(result.dict())
            except Exception as e:
                logger.warning(f"Failed to save to Firestore: {e}")

        logger.info(f"Analysis complete: {file_id} - Malicious: {result.is_malicious}")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed for {file_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


async def _analyze_content(content: bytes, filename: str, file_hash: str) -> Dict:
    """
    Internal function to perform actual malware analysis.

    Args:
        content: File content as bytes
        filename: Original filename
        file_hash: SHA256 hash

    Returns:
        Analysis results dictionary
    """
    result = {
        "is_malicious": False,
        "confidence": 0.0,
        "risk_score": 0,
        "llm_source": "unknown",
        "detected_patterns": [],
        "evasion_techniques": [],
        "malicious_indicators": [],
        "suspicious_imports": [],
        "yara_matches": [],
        "entropy": 0.0,
        "obfuscation_level": "none"
    }

    try:
        # Decode content to string for text-based analysis
        try:
            code = content.decode('utf-8', errors='ignore')
        except:
            code = content.decode('latin-1', errors='ignore')

        # 1. Pattern Detection
        if pattern_detector:
            logger.info("Running pattern detection...")
            pattern_result = pattern_detector.analyze(code)
            
            result["is_malicious"] = pattern_result.get("is_ai_generated", False)
            result["confidence"] = pattern_result.get("confidence", 0.0)
            result["risk_score"] = pattern_result.get("risk_score", 0)
            result["llm_source"] = pattern_result.get("llm_source", "unknown")
            result["detected_patterns"] = pattern_result.get("detected_patterns", [])
            result["evasion_techniques"] = pattern_result.get("evasion_techniques", [])
            result["malicious_indicators"] = pattern_result.get("malicious_indicators", [])
            result["suspicious_imports"] = pattern_result.get("suspicious_imports", [])
            result["entropy"] = pattern_result.get("entropy", 0.0)
            result["obfuscation_level"] = pattern_result.get("obfuscation_level", "none")

        # 2. YARA Scanning
        if yara_scanner and yara_scanner.is_enabled():
            logger.info("Running YARA scan...")
            yara_matches = yara_scanner.scan(content)
            result["yara_matches"] = yara_matches
            
            if yara_matches:
                result["is_malicious"] = True
                severity_score = yara_scanner.get_severity_score(yara_matches)
                result["risk_score"] = max(result["risk_score"], severity_score)
                result["confidence"] = min(1.0, result["confidence"] + 0.2)

        # 3. VirusTotal Check (if API key available)
        if VIRUSTOTAL_API_KEY:
            logger.info("Checking VirusTotal...")
            vt_result = await _check_virustotal(file_hash)
            result["virustotal"] = vt_result

        # 4. GPU Service (if available)
        if GPU_SERVICE_URL:
            logger.info("Sending to GPU service...")
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        f"{GPU_SERVICE_URL}/analyze",
                        json={"code": code, "filename": filename}
                    )
                    if response.status_code == 200:
                        gpu_result = response.json()
                        result["gpu_analysis"] = gpu_result
            except Exception as e:
                logger.warning(f"GPU service error: {e}")

        # Final verdict
        if result["risk_score"] > 50 or result["confidence"] > 0.6:
            result["is_malicious"] = True

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        result["error"] = str(e)

    return result


async def _check_virustotal(file_hash: str) -> Dict:
    """
    Check file hash against VirusTotal API.

    Args:
        file_hash: SHA256 hash of file

    Returns:
        VirusTotal scan results
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "API key not configured"}

    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values())
                }
            elif response.status_code == 404:
                return {"found": False, "message": "File not found in VirusTotal"}
            else:
                return {"error": f"VT API error: {response.status_code}"}

    except Exception as e:
        logger.error(f"VirusTotal check failed: {e}")
        return {"error": str(e)}


@app.get("/api/status/{file_id}")
async def get_status(file_id: str):
    """Get analysis status by file ID."""
    # Check local storage first
    result_path = LOCAL_STORAGE_PATH / "results" / f"{file_id}.json"
    
    if result_path.exists():
        with open(result_path, 'r') as f:
            return f.read()

    # Check Firestore if cloud mode
    if CLOUD_MODE and db:
        try:
            doc = db.collection('analyses').document(file_id).get()
            if doc.exists:
                return doc.to_dict()
        except Exception as e:
            logger.error(f"Firestore query failed: {e}")

    raise HTTPException(status_code=404, detail="Analysis not found")


@app.get("/api/history")
async def get_history(limit: int = 10):
    """Get recent analysis history."""
    # Read from local storage
    results_dir = LOCAL_STORAGE_PATH / "results"
    result_files = sorted(
        results_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )[:limit]

    analyses = []
    for file_path in result_files:
        try:
            with open(file_path, 'r') as f:
                import json
                analyses.append(json.load(f))
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")

    return {"total": len(analyses), "analyses": analyses}


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8080))
    logger.info(f"Starting ShadowHunter AI Backend on port {port}")
    logger.info(f"Mode: {'Cloud' if CLOUD_MODE else 'Local'}")
    logger.info(f"Analyzers: Pattern={pattern_detector is not None}, YARA={yara_scanner is not None}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
