"""
ShadowHunter AI - GPU Analysis Service
Main analysis engine using Gemma 2 9B model with GPU acceleration
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google.cloud import storage
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import os
import sys
import json
import re
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.patterns import AICodePatternDetector
from analyzer.yara_scanner import YaraScanner
from integrations.virustotal import scan_file_hash

app = FastAPI(
    title="ShadowHunter GPU Service",
    description="GPU-accelerated malware analysis",
    version="1.0.0"
)

# Global model cache (loaded once at startup)
MODEL_CACHE = {}

# Configuration
USE_GPU = os.getenv("USE_GPU", "true").lower() == "true"
MODEL_NAME = os.getenv("MODEL_NAME", "google/gemma-2-9b-it")


class AnalysisRequest(BaseModel):
    file_id: str
    gcs_path: str
    file_hash: str
    file_name: str = "unknown"


def load_model():
    """
    Load Gemma 2 9B model (cached globally)
    This runs once at container startup
    """
    if "model" in MODEL_CACHE:
        return MODEL_CACHE["model"], MODEL_CACHE["tokenizer"]

    try:
        print(f"Loading model: {MODEL_NAME}")
        print(f"GPU available: {torch.cuda.is_available()}")

        if torch.cuda.is_available():
            print(f"GPU: {torch.cuda.get_device_name(0)}")
            print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")

        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

        # Load model with appropriate settings
        if USE_GPU and torch.cuda.is_available():
            model = AutoModelForCausalLM.from_pretrained(
                MODEL_NAME,
                device_map="cuda",
                torch_dtype=torch.bfloat16,
                low_cpu_mem_usage=True,
            )
        else:
            # CPU fallback (for development/testing)
            print("WARNING: Running on CPU (slow!)")
            model = AutoModelForCausalLM.from_pretrained(
                MODEL_NAME,
                device_map="cpu",
                torch_dtype=torch.float32,
            )

        MODEL_CACHE["model"] = model
        MODEL_CACHE["tokenizer"] = tokenizer

        print("Model loaded successfully!")
        return model, tokenizer

    except Exception as e:
        print(f"Error loading model: {e}")
        raise


def analyze_with_gemma(code: str, max_length: int = 2000) -> dict:
    """
    Use Gemma 2 to analyze code for malicious intent

    Args:
        code: Source code to analyze
        max_length: Maximum code length to analyze

    Returns:
        Analysis results from Gemma
    """

    try:
        model, tokenizer = load_model()

        # Truncate code if too long
        code_sample = code[:max_length]

        prompt = f"""Analyze this code for malicious behavior, obfuscation, and AI-generation patterns.

Code:
```python
{code_sample}
```

Provide a detailed security analysis in JSON format:
{{
    "is_malicious": true/false,
    "confidence": 0.0-1.0,
    "malware_type": "string (e.g., ransomware, keylogger, trojan)",
    "obfuscation_detected": true/false,
    "ai_generated_confidence": 0.0-1.0,
    "key_indicators": ["list", "of", "suspicious", "patterns"],
    "threat_level": "low/medium/high/critical"
}}

JSON Response:"""

        inputs = tokenizer(prompt, return_tensors="pt")

        if USE_GPU and torch.cuda.is_available():
            inputs = inputs.to("cuda")

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.3,
                do_sample=True,
                top_p=0.9,
            )

        response = tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Extract JSON from response
        try:
            # Try to find JSON block in response
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Fallback: return structured error
        return {
            "is_malicious": False,
            "confidence": 0.0,
            "malware_type": "unknown",
            "obfuscation_detected": False,
            "ai_generated_confidence": 0.0,
            "key_indicators": [],
            "threat_level": "unknown",
            "error": "Failed to parse Gemma response",
            "raw_response": response[:500]  # Include partial response for debugging
        }

    except Exception as e:
        return {
            "error": f"Gemma analysis failed: {str(e)}",
            "is_malicious": False,
            "confidence": 0.0
        }


@app.on_event("startup")
async def startup_event():
    """Pre-load model at startup to avoid cold start delays"""
    print("Starting ShadowHunter GPU Service...")
    try:
        load_model()
        print("Ready to analyze!")
    except Exception as e:
        print(f"Warning: Model loading failed: {e}")
        print("Service will attempt to load model on first request")


@app.get("/")
async def root():
    return {
        "service": "ShadowHunter GPU Analysis Service",
        "status": "healthy",
        "gpu_available": torch.cuda.is_available(),
        "model_loaded": "model" in MODEL_CACHE
    }


@app.get("/health")
async def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "gpu_available": torch.cuda.is_available(),
        "model_loaded": "model" in MODEL_CACHE,
        "torch_version": torch.__version__,
        "cuda_version": torch.version.cuda if torch.cuda.is_available() else None
    }


@app.post("/analyze")
async def analyze(request: AnalysisRequest):
    """
    Main analysis endpoint
    Orchestrates all detection methods
    """

    try:
        print(f"Analyzing file: {request.file_id}")

        # 1. Download file from Cloud Storage
        storage_client = storage.Client()
        bucket_name = request.gcs_path.split("/")[2]
        blob_path = "/".join(request.gcs_path.split("/")[3:])

        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        file_content = blob.download_as_bytes()

        print(f"Downloaded {len(file_content)} bytes")

        # Try to decode as text
        try:
            code_text = file_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                code_text = file_content.decode('latin-1')
            except:
                code_text = ""

        # 2. Pattern Analysis
        print("Running pattern detection...")
        pattern_detector = AICodePatternDetector()
        pattern_results = pattern_detector.analyze(code_text)

        # 3. YARA Scanning
        print("Running YARA scan...")
        try:
            yara_scanner = YaraScanner()
            yara_results = yara_scanner.scan(file_content)
            yara_severity = yara_scanner.get_severity_score(yara_results)
        except Exception as e:
            print(f"YARA scan failed: {e}")
            yara_results = []
            yara_severity = 0

        # 4. VirusTotal Check
        print("Checking VirusTotal...")
        try:
            vt_results = await scan_file_hash(request.file_hash)
        except Exception as e:
            print(f"VirusTotal check failed: {e}")
            vt_results = {"error": str(e), "exists": False}

        # 5. Gemma 2 Deep Analysis (if text content available)
        print("Running Gemma analysis...")
        if code_text:
            gemma_results = analyze_with_gemma(code_text)
        else:
            gemma_results = {
                "error": "Binary file - cannot analyze with Gemma",
                "is_malicious": False
            }

        # 6. Combine results and calculate final verdict
        print("Calculating final verdict...")

        is_malicious = (
            pattern_results["is_ai_generated"] or
            len(yara_results) > 0 or
            gemma_results.get("is_malicious", False)
        )

        # Calculate combined confidence
        confidence_scores = [
            pattern_results["confidence"],
            yara_severity / 100,
            gemma_results.get("confidence", 0.0)
        ]
        avg_confidence = sum(confidence_scores) / len(confidence_scores)

        # Determine risk level
        risk_level = _calculate_risk_level(
            pattern_results,
            yara_results,
            vt_results,
            gemma_results
        )

        # Determine threat category
        threat_category = _determine_threat_category(
            pattern_results,
            yara_results,
            gemma_results
        )

        # Build final response
        final_verdict = {
            "file_id": request.file_id,
            "file_name": request.file_name,
            "file_hash": request.file_hash,
            "file_size": len(file_content),
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z",

            "detection": {
                "is_malicious": is_malicious,
                "is_ai_generated": pattern_results["is_ai_generated"],
                "confidence": round(avg_confidence, 3),
                "llm_source": pattern_results["llm_source"],
            },

            "pattern_analysis": {
                "detected_patterns": pattern_results["detected_patterns"],
                "evasion_techniques": pattern_results["evasion_techniques"],
                "malicious_indicators": pattern_results["malicious_indicators"],
                "entropy": pattern_results["entropy"],
                "obfuscation_level": pattern_results["obfuscation_level"],
                "risk_score": pattern_results["risk_score"],
            },

            "yara_matches": [
                {
                    "rule": match["rule"],
                    "severity": match["meta"].get("severity", "medium"),
                    "description": match["meta"].get("description", ""),
                }
                for match in yara_results
            ],

            "virustotal": vt_results,

            "gemma_analysis": {
                "is_malicious": gemma_results.get("is_malicious", False),
                "confidence": gemma_results.get("confidence", 0.0),
                "malware_type": gemma_results.get("malware_type", "unknown"),
                "threat_level": gemma_results.get("threat_level", "unknown"),
            },

            "risk_assessment": {
                "risk_level": risk_level,
                "threat_category": threat_category,
                "recommended_action": "QUARANTINE" if risk_level in ["HIGH", "CRITICAL"] else "REVIEW",
            }
        }

        print(f"Analysis complete. Malicious: {is_malicious}")
        return final_verdict

    except Exception as e:
        print(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


def _calculate_risk_level(pattern_results, yara_results, vt_results, gemma_results) -> str:
    """Calculate overall risk level"""
    score = 0

    # Pattern detection
    if pattern_results["is_ai_generated"]:
        score += 40

    # YARA matches
    score += len(yara_results) * 15

    # VirusTotal
    if vt_results.get("exists") and vt_results.get("malicious", 0) > 5:
        score += 30

    # Gemma analysis
    if gemma_results.get("is_malicious"):
        score += 25

    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def _determine_threat_category(pattern_results, yara_results, gemma_results) -> str:
    """Determine malware category"""

    # Check YARA matches first
    for match in yara_results:
        threat_type = match.get("meta", {}).get("threat_type")
        if threat_type:
            return threat_type.upper()

    # Check Gemma results
    gemma_type = gemma_results.get("malware_type", "").lower()
    if gemma_type and gemma_type != "unknown":
        return gemma_type.upper()

    # Check pattern results
    techniques = pattern_results.get("evasion_techniques", [])
    if any("inject" in str(t).lower() for t in techniques):
        return "CODE_INJECTION"
    elif any("ransomware" in str(t).lower() for t in techniques):
        return "RANSOMWARE"
    elif "polymorphic" in str(techniques).lower():
        return "POLYMORPHIC_MALWARE"
    else:
        return "GENERIC_MALWARE"


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8081))
    uvicorn.run(app, host="0.0.0.0", port=port)
