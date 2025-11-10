#!/usr/bin/env python3
"""
Ghidra Binary Analysis Service
FastAPI microservice for binary malware analysis
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google.cloud import storage
import subprocess
import json
import os
import tempfile
import uuid
import shutil
from pathlib import Path

app = FastAPI(title="Ghidra Analysis Service")

GHIDRA_PATH = os.getenv("GHIDRA_PATH", "/opt/ghidra")
GHIDRA_HEADLESS = f"{GHIDRA_PATH}/support/analyzeHeadless"


class BinaryAnalysisRequest(BaseModel):
    file_id: str
    gcs_path: str
    file_hash: str
    filetype: str  # exe, dll, elf, so, etc.


@app.get("/")
async def root():
    return {
        "service": "Ghidra Binary Analysis Service",
        "status": "healthy",
        "ghidra_version": "11.0"
    }


@app.get("/health")
async def health():
    """Health check."""
    ghidra_exists = os.path.exists(GHIDRA_HEADLESS)
    return {
        "status": "healthy" if ghidra_exists else "unhealthy",
        "ghidra_available": ghidra_exists,
        "ghidra_path": GHIDRA_PATH
    }


@app.post("/analyze")
async def analyze_binary(request: BinaryAnalysisRequest):
    """Analyze binary file using Ghidra headless mode."""
    tempdir = None
    
    try:
        print(f"Analyzing binary: {request.file_id}")
        
        # Create temporary directory
        tempdir = tempfile.mkdtemp()
        project_name = f"project_{uuid.uuid4().hex}"
        
        # Download binary from GCS
        print("Downloading from Cloud Storage...")
        storage_client = storage.Client()
        bucket_name = request.gcs_path.split("/")[2]
        blob_path = "/".join(request.gcs_path.split("/")[3:])
        
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        binary_path = os.path.join(tempdir, "binary_sample")
        blob.download_to_filename(binary_path)
        
        file_size = os.path.getsize(binary_path)
        print(f"Downloaded: {file_size} bytes")
        
        # Make executable for ELF files
        os.chmod(binary_path, 0o755)
        
        # Prepare output file
        output_file = os.path.join(tempdir, "ghidra_analysis.json")
        
        # Run Ghidra headless analysis
        cmd = [
            GHIDRA_HEADLESS,
            tempdir,
            project_name,
            "-import", binary_path,
            "-scriptPath", "/app",
            "-postScript", "ghidra_script.py",
            "-deleteProject"
        ]
        
        print(f"Running Ghidra: {' '.join(cmd)}")
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,  # 3 minutes max
            cwd="/app"
        )
        
        print(f"Ghidra exit code: {process.returncode}")
        
        if process.returncode != 0:
            print(f"STDERR: {process.stderr}")
            raise Exception(f"Ghidra analysis failed: {process.stderr[:500]}")
        
        # Read analysis results
        result_file = "/tmp/ghidra_analysis.json"
        if not os.path.exists(result_file):
            raise Exception("Ghidra did not produce output file")
        
        with open(result_file, 'r') as f:
            ghidra_results = json.load(f)
        
        print(f"Analysis complete. Functions: {len(ghidra_results.get('functions', []))}")
        
        # Build enhanced results
        enhanced_results = {
            "file_id": request.file_id,
            "file_hash": request.file_hash,
            "filetype": request.filetype,
            "file_size": file_size,
            "analysis_status": "completed",
            "ghidra_analysis": ghidra_results,
            "summary": {
                "total_functions": len(ghidra_results.get("functions", [])),
                "suspicious_patterns_count": len(ghidra_results.get("suspicious_patterns", [])),
                "total_imports": len(ghidra_results.get("imports", [])),
                "syscalls_detected": len(ghidra_results.get("syscalls", [])),
                "strings_extracted": len(ghidra_results.get("strings", [])),
                "risk_indicators": ghidra_results.get("suspicious_patterns", [])[:5]
            }
        }
        
        return enhanced_results
    
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Analysis timeout (180s)")
    except Exception as e:
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Cleanup
        if tempdir and os.path.exists(tempdir):
            try:
                shutil.rmtree(tempdir, ignore_errors=True)
            except:
                pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8081))
    uvicorn.run(app, host="0.0.0.0", port=port)
