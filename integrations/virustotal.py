"""
ShadowHunter AI - VirusTotal Integration
Compare AI-generated malware detection with traditional AV engines
"""

import httpx
import os
import hashlib
from typing import Dict, Optional
import asyncio


VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_API_URL = "https://www.virustotal.com/api/v3"


async def scan_file_hash(file_hash: str) -> Optional[Dict]:
    """
    Check if file hash exists in VirusTotal database

    Args:
        file_hash: SHA256 hash of the file

    Returns:
        Detection statistics or None if not found
    """

    if not VT_API_KEY:
        return {
            "error": "VirusTotal API key not configured",
            "exists": False
        }

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{VT_API_URL}/files/{file_hash}",
                headers=headers,
                timeout=30.0
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']
                stats = attributes['last_analysis_stats']

                return {
                    "exists": True,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "harmless": stats.get('harmless', 0),
                    "total_engines": sum(stats.values()),
                    "detection_rate": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    "sha256": file_hash,
                    "names": attributes.get('names', []),
                    "first_submission": attributes.get('first_submission_date', 'N/A'),
                    "last_analysis": attributes.get('last_analysis_date', 'N/A')
                }

            elif response.status_code == 404:
                return {
                    "exists": False,
                    "message": "File not found in VirusTotal database"
                }

            else:
                return {
                    "error": f"VirusTotal API error: {response.status_code}",
                    "exists": False
                }

        except httpx.TimeoutException:
            return {
                "error": "VirusTotal API timeout",
                "exists": False
            }
        except Exception as e:
            return {
                "error": f"VirusTotal request failed: {str(e)}",
                "exists": False
            }


async def upload_and_scan(file_content: bytes, filename: str = "sample") -> Dict:
    """
    Upload file to VirusTotal for scanning
    Note: This is rate-limited (4 requests/minute for free tier)

    Args:
        file_content: Raw file bytes
        filename: Original filename

    Returns:
        Scan request status
    """

    if not VT_API_KEY:
        return {
            "error": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    async with httpx.AsyncClient() as client:
        try:
            # Upload file
            files = {
                'file': (filename, file_content)
            }

            response = await client.post(
                f"{VT_API_URL}/files",
                headers=headers,
                files=files,
                timeout=60.0
            )

            if response.status_code == 200:
                data = response.json()
                analysis_id = data['data']['id']

                return {
                    "status": "scanning",
                    "analysis_id": analysis_id,
                    "message": "File uploaded successfully. Analysis in progress."
                }

            else:
                return {
                    "error": f"Upload failed: {response.status_code}",
                    "message": response.text
                }

        except Exception as e:
            return {
                "error": f"Upload failed: {str(e)}"
            }


async def get_analysis_results(analysis_id: str) -> Dict:
    """
    Get analysis results by analysis ID

    Args:
        analysis_id: VirusTotal analysis ID

    Returns:
        Analysis results
    """

    if not VT_API_KEY:
        return {
            "error": "VirusTotal API key not configured"
        }

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{VT_API_URL}/analyses/{analysis_id}",
                headers=headers,
                timeout=30.0
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']

                if attributes['status'] == 'completed':
                    stats = attributes['stats']

                    return {
                        "status": "completed",
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                        "total_engines": sum(stats.values()),
                        "detection_rate": f"{stats.get('malicious', 0)}/{sum(stats.values())}"
                    }
                else:
                    return {
                        "status": attributes['status'],
                        "message": "Analysis still in progress"
                    }

            else:
                return {
                    "error": f"Failed to retrieve results: {response.status_code}"
                }

        except Exception as e:
            return {
                "error": f"Request failed: {str(e)}"
            }


def calculate_file_hash(file_content: bytes) -> str:
    """
    Calculate SHA256 hash of file content

    Args:
        file_content: Raw file bytes

    Returns:
        SHA256 hash string
    """
    return hashlib.sha256(file_content).hexdigest()


async def comprehensive_scan(file_content: bytes, filename: str = "sample") -> Dict:
    """
    Perform comprehensive VirusTotal scan:
    1. Check if hash exists in database
    2. If not, upload and scan
    3. Wait for results (with timeout)

    Args:
        file_content: Raw file bytes
        filename: Original filename

    Returns:
        Complete scan results
    """

    file_hash = calculate_file_hash(file_content)

    # First, check if file already exists
    print(f"Checking VirusTotal database for hash: {file_hash}")
    hash_result = await scan_file_hash(file_hash)

    if hash_result.get("exists"):
        print("File found in VirusTotal database!")
        return hash_result

    # File not in database, upload for scanning
    print("File not in database. Uploading for scanning...")
    upload_result = await upload_and_scan(file_content, filename)

    if "analysis_id" not in upload_result:
        return upload_result

    analysis_id = upload_result["analysis_id"]

    # Wait for analysis to complete (max 60 seconds)
    print("Waiting for analysis to complete...")
    for attempt in range(12):  # 12 * 5 = 60 seconds
        await asyncio.sleep(5)

        result = await get_analysis_results(analysis_id)

        if result.get("status") == "completed":
            print("Analysis completed!")
            return result

    # Timeout
    return {
        "status": "timeout",
        "message": "Analysis timeout. Check back later.",
        "analysis_id": analysis_id
    }


# Standalone test
if __name__ == "__main__":
    import sys

    async def test():
        # Test with EICAR test file (standard AV test string)
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

        print("Testing VirusTotal integration...")
        print("=" * 50)

        # Calculate hash
        file_hash = calculate_file_hash(eicar)
        print(f"File hash: {file_hash}")

        # Scan hash
        result = await scan_file_hash(file_hash)
        print("\nScan result:")
        print(result)

    # Run test
    asyncio.run(test())
