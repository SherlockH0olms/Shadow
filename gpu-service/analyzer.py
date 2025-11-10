#!/usr/bin/env python3
"""
ShadowHunter AI - GPU Analysis Service
Main analysis engine using Gemma 2 9B model with GPU acceleration
ENHANCED with Ghidra Binary Analysis Support
"""

import os
import sys
import json
import re
import logging
from datetime import datetime
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx

try:
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False
    logging.warning("PyTorch not available - GPU analysis disabled")

try:
    from google.cloud import storage
    CLOUD_AVAILABLE = True
except ImportError:
    CLOUD_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="ShadowHunter GPU Analysis Service",
    version="2.0.0"
)

# Configuration
USE_GPU = os.getenv("USE_GPU", "true").lower() == "true"
MODEL_NAME = os.getenv("MODEL_NAME", "google/gemma-2-9b-it")
GHIDRA_SERVICE_URL = os.getenv("GHIDRA_SERVICE_URL", "")  # NEW

# Model cache
MODEL_CACHE = {}


class AnalysisRequest(BaseModel):
    file_id: str
    gcs_path: str
    file_hash: str
    filename: str = "unknown"
    filetype: str = "text"  # NEW: text, exe, dll, elf, so, bin


def load_model():
    """Load Gemma 2 9B model (cached globally)."""
    if "model" in MODEL_CACHE:
        return MODEL_CACHE["model"], MODEL_CACHE["tokenizer"]

    if not GPU_AVAILABLE:
        raise Exception("PyTorch not available")

    try:
        logger.info(f"Loading model: {MODEL_NAME}")
        logger.info(f"GPU available: {torch.cuda.is_available()}")
        
        if torch.cuda.is_available():
            logger.info(f"GPU: {torch.cuda.get_device_name(0)}")
            logger.info(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        
        if USE_GPU and torch.cuda.is_available():
            model = AutoModelForCausalLM.from_pretrained(
                MODEL_NAME,
                device_map="cuda",
                torch_dtype=torch.bfloat16,
            )
        else:
            model = AutoModelForCausalLM.from_pretrained(MODEL_NAME)

        MODEL_CACHE["model"] = model
        MODEL_CACHE["tokenizer"] = tokenizer

        logger.info("✓ Model loaded successfully")
        return model, tokenizer

    except Exception as e:
        logger.error(f"Model loading failed: {e}")
        raise


async def analyze_with_gemma(code: str, max_length: int = 2000) -> Dict:
    """Analyze code with Gemma 2 9B model."""
    try:
        model, tokenizer = load_model()

        # Truncate code if too long
        if len(code) > max_length:
            code = code[:max_length] + "\n# ... [truncated]"

        prompt = f"""You are a malware analysis expert. Analyze this code and determine:
1. Is it malicious? (yes/no)
2. Confidence level (0.0-1.0)
3. Malware type (if applicable)
4. Key malicious behaviors

Code:
```
{code}
```

Respond in JSON format:
{{
  "is_malicious": true/false,
  "confidence": 0.0-1.0,
  "malware_type": "string or null",
  "key_indicators": ["behavior1", "behavior2"],
  "threat_level": "critical/high/medium/low/none"
}}
"""

        inputs = tokenizer(prompt, return_tensors="pt", max_length=4096, truncation=True)
        
        if USE_GPU and torch.cuda.is_available():
            inputs = inputs.to("cuda")

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.3,
                do_sample=True,
            )

        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Extract JSON from response
        json_match = re.search(r'\{[^}]+\}', response, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            return result
        else:
            logger.warning("Could not parse Gemma response")
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "malware_type": "unknown",
                "key_indicators": [],
                "threat_level": "unknown",
                "error": "Failed to parse response"
            }

    except Exception as e:
        logger.error(f"Gemma analysis failed: {e}")
        return {
            "error": str(e),
            "is_malicious": False,
            "confidence": 0.0
        }


async def analyze_binary_with_ghidra(request: AnalysisRequest, ghidra_data: dict) -> dict:
    """Analyze Ghidra decompilation results with AI."""
    logger.info("Analyzing Ghidra results with AI...")

    try:
        # Extract key information from Ghidra
        decompiled_functions = ghidra_data.get("ghidra_analysis", {}).get("decompiled_code", [])
        suspicious_patterns = ghidra_data.get("ghidra_analysis", {}).get("suspicious_patterns", [])
        imports = ghidra_data.get("ghidra_analysis", {}).get("imports", [])

        # Prepare context for AI
        gemma_result = {}
        if decompiled_functions:
            sample_code = decompiled_functions[0].get("code", "")
            gemma_result = await analyze_with_gemma(sample_code, max_length=1000)

        # Calculate risk
        risk_score = len(suspicious_patterns) * 10
        for imp in imports:
            if any(dangerous in imp.get("name", "") for dangerous in ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]):
                risk_score += 20

        is_malicious = risk_score > 50 or gemma_result.get("is_malicious", False)

        final_verdict = {
            "file_id": request.file_id,
            "filename": request.filename,
            "file_hash": request.file_hash,
            "file_size": ghidra_data.get("file_size", 0),
            "analysis_type": "binary_with_ghidra",
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
            "detection": {
                "is_malicious": is_malicious,
                "confidence": min(risk_score / 100, 1.0),
                "threat_type": gemma_result.get("malware_type", "unknown"),
            },
            "ghidra_analysis": ghidra_data.get("ghidra_analysis", {}),
            "ghidra_summary": ghidra_data.get("summary", {}),
            "ai_analysis": {"gemma_analysis": gemma_result},
            "risk_assessment": {
                "risk_level": calculate_risk_level(risk_score),
                "risk_score": min(risk_score, 100),
                "critical_findings": suspicious_patterns[:5],
                "recommended_action": "QUARANTINE" if is_malicious else "REVIEW"
            }
        }

        return final_verdict

    except Exception as e:
        logger.error(f"Binary analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def calculate_risk_level(score: int) -> str:
    """Calculate risk level from score."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "NONE"


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8082))
    logger.info(f"Starting GPU service on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
