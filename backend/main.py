"""
ShadowHunter AI - Backend API Service
Main FastAPI application for file upload and analysis orchestration
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from google.cloud import storage, firestore
import hashlib
import uuid
from datetime import datetime
import httpx
import os
from typing import Dict, Optional
from pydantic import BaseModel

app = FastAPI(
    title="ShadowHunter AI API",
    description="AI-Generated Malware Detection Platform",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For demo - restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Google Cloud clients
storage_client = storage.Client()
db = firestore.Client()

# Environment variables
GPU_SERVICE_URL = os.getenv("GPU_SERVICE_URL", "http://localhost:8081")
BUCKET_NAME = os.getenv("STORAGE_BUCKET", "shadowhunter-samples")
RESULTS_BUCKET = os.getenv("RESULTS_BUCKET", "shadowhunter-results")

# Models
class AnalysisStatus(BaseModel):
    file_id: str
    status: str
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict] = None
    error: Optional[str] = None


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": "ShadowHunter AI Backend",
        "status": "healthy",
        "version": "1.0.0"
    }


@app.get("/health")
async def health():
    """Detailed health check"""
    try:
        # Check GCS connectivity
        bucket = storage_client.bucket(BUCKET_NAME)
        bucket.exists()

        # Check Firestore connectivity
        db.collection('health').document('check').get()

        return {
            "status": "healthy",
            "storage": "connected",
            "database": "connected",
            "gpu_service": GPU_SERVICE_URL
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e)
        }


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """
    Main endpoint for malware analysis

    Args:
        file: Uploaded file (Python, PE, DLL, JavaScript, PowerShell)

    Returns:
        Analysis results including AI-generation detection
    """

    # Generate unique analysis ID
    file_id = str(uuid.uuid4())

    try:
        # Read file content
        content = await file.read()
        file_size = len(content)

        # Calculate file hash
        file_hash = hashlib.sha256(content).hexdigest()

        # Validate file size (max 10MB for demo)
        if file_size > 10 * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail="File too large. Maximum size: 10MB"
            )

        # Upload to Cloud Storage
        bucket = storage_client.bucket(BUCKET_NAME)
        blob_path = f"{file_id}/{file.filename}"
        blob = bucket.blob(blob_path)
        blob.upload_from_string(content)

        gcs_path = f"gs://{BUCKET_NAME}/{blob_path}"

        # Create Firestore document for tracking
        doc_ref = db.collection('analyses').document(file_id)
        doc_ref.set({
            'file_id': file_id,
            'file_name': file.filename,
            'file_hash': file_hash,
            'file_size': file_size,
            'status': 'pending',
            'created_at': firestore.SERVER_TIMESTAMP,
            'gcs_path': gcs_path
        })

        # Trigger GPU analysis service
        async with httpx.AsyncClient(timeout=300.0) as client:
            try:
                response = await client.post(
                    f"{GPU_SERVICE_URL}/analyze",
                    json={
                        "file_id": file_id,
                        "gcs_path": gcs_path,
                        "file_hash": file_hash,
                        "file_name": file.filename
                    }
                )

                if response.status_code != 200:
                    raise HTTPException(
                        status_code=500,
                        detail=f"GPU service error: {response.text}"
                    )

                analysis_result = response.json()

                # Update Firestore with results
                doc_ref.update({
                    'status': 'completed',
                    'result': analysis_result,
                    'completed_at': firestore.SERVER_TIMESTAMP
                })

                return {
                    "file_id": file_id,
                    "file_name": file.filename,
                    "file_hash": file_hash,
                    "status": "completed",
                    "result": analysis_result
                }

            except httpx.RequestError as e:
                # Update Firestore with error
                doc_ref.update({
                    'status': 'error',
                    'error': str(e),
                    'completed_at': firestore.SERVER_TIMESTAMP
                })

                raise HTTPException(
                    status_code=500,
                    detail=f"Analysis service unavailable: {str(e)}"
                )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )


@app.get("/api/status/{file_id}")
async def get_analysis_status(file_id: str):
    """
    Get analysis status and results by file ID

    Args:
        file_id: Unique analysis identifier

    Returns:
        Analysis status and results (if completed)
    """

    try:
        doc_ref = db.collection('analyses').document(file_id)
        doc = doc_ref.get()

        if not doc.exists:
            raise HTTPException(
                status_code=404,
                detail=f"Analysis not found: {file_id}"
            )

        data = doc.to_dict()

        # Convert Firestore timestamps to ISO format
        if 'created_at' in data and data['created_at']:
            data['created_at'] = data['created_at'].isoformat()
        if 'completed_at' in data and data['completed_at']:
            data['completed_at'] = data['completed_at'].isoformat()

        return data

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve status: {str(e)}"
        )


@app.get("/api/history")
async def get_analysis_history(limit: int = 10):
    """
    Get recent analysis history

    Args:
        limit: Number of recent analyses to return (default: 10)

    Returns:
        List of recent analyses
    """

    try:
        docs = (
            db.collection('analyses')
            .order_by('created_at', direction=firestore.Query.DESCENDING)
            .limit(limit)
            .stream()
        )

        results = []
        for doc in docs:
            data = doc.to_dict()

            # Convert timestamps
            if 'created_at' in data and data['created_at']:
                data['created_at'] = data['created_at'].isoformat()
            if 'completed_at' in data and data['completed_at']:
                data['completed_at'] = data['completed_at'].isoformat()

            results.append(data)

        return {
            "total": len(results),
            "analyses": results
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve history: {str(e)}"
        )


@app.delete("/api/analysis/{file_id}")
async def delete_analysis(file_id: str):
    """
    Delete analysis and associated files

    Args:
        file_id: Unique analysis identifier

    Returns:
        Deletion confirmation
    """

    try:
        # Get document
        doc_ref = db.collection('analyses').document(file_id)
        doc = doc_ref.get()

        if not doc.exists:
            raise HTTPException(
                status_code=404,
                detail=f"Analysis not found: {file_id}"
            )

        data = doc.to_dict()

        # Delete file from Cloud Storage
        gcs_path = data.get('gcs_path', '')
        if gcs_path:
            bucket_name = gcs_path.split('/')[2]
            blob_path = '/'.join(gcs_path.split('/')[3:])

            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(blob_path)

            if blob.exists():
                blob.delete()

        # Delete Firestore document
        doc_ref.delete()

        return {
            "status": "deleted",
            "file_id": file_id
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete analysis: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
