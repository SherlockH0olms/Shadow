"""
ShadowHunter AI - Integrations Module
"""

from .virustotal import scan_file_hash, upload_and_scan, comprehensive_scan

__all__ = ['scan_file_hash', 'upload_and_scan', 'comprehensive_scan']
