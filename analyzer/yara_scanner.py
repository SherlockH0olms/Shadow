#!/usr/bin/env python3
"""
ShadowHunter AI - YARA Scanner
Scans files using custom YARA rules for malware detection

Production-ready implementation with comprehensive error handling
"""

import os
import logging
from pathlib import Path
from typing import List, Dict, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("yara-python not installed. YARA scanning disabled.")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class YaraScanner:
    """
    YARA-based malware scanner for AI-generated threats.
    Uses custom rules to detect malicious patterns.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize YARA scanner with rules.

        Args:
            rules_dir: Path to YARA rules directory (default: ./yara_rules)
        """
        if not YARA_AVAILABLE:
            logger.error("YARA module not available. Install with: pip install yara-python")
            self.rules = None
            self.enabled = False
            return

        self.enabled = True

        if rules_dir is None:
            rules_dir = Path(__file__).parent / "yara_rules"
        else:
            rules_dir = Path(rules_dir)

        self.rules_dir = rules_dir
        
        if not self.rules_dir.exists():
            logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            logger.info("Creating default rules directory...")
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            self._create_default_rules()

        self.rules = self._compile_rules()

    def _create_default_rules(self):
        """Create default YARA rules if directory is empty."""
        default_rule = '''
rule AI_Generated_Malware {
    meta:
        description = "Detects AI-generated malware patterns"
        author = "ShadowHunter AI"
        severity = "high"
        llm_source = "generic"
    
    strings:
        $ai1 = "AI generated" nocase
        $ai2 = "LLM powered" nocase
        $ai3 = "GPT assisted" nocase
        $evasion1 = "amsi bypass" nocase
        $evasion2 = "etw patch" nocase
        $windows_api = "NtAllocateVirtualMemory"
        $quantum = "CRYSTALS-Kyber"
    
    condition:
        any of ($ai*) or 2 of ($evasion*, $windows_api, $quantum)
}
'''
        default_file = self.rules_dir / "default.yar"
        try:
            with open(default_file, 'w') as f:
                f.write(default_rule)
            logger.info(f"Created default YARA rule: {default_file}")
        except Exception as e:
            logger.error(f"Failed to create default rule: {e}")

    def _compile_rules(self) -> Optional[yara.Rules]:
        """
        Compile all YARA rules from directory.

        Returns:
            Compiled YARA rules object or None if compilation fails
        """
        try:
            rule_files = list(self.rules_dir.glob("*.yar"))

            if not rule_files:
                logger.warning(f"No .yar files found in {self.rules_dir}")
                return None

            # Create rules dictionary for compilation
            rules_dict = {}
            for f in rule_files:
                try:
                    # Validate file is readable
                    with open(f, 'r') as rf:
                        content = rf.read()
                        if content.strip():
                            rules_dict[str(f.stem)] = str(f)
                except Exception as e:
                    logger.warning(f"Skipping invalid rule file {f}: {e}")
                    continue

            if not rules_dict:
                logger.error("No valid YARA rules found")
                return None

            logger.info(f"Compiling {len(rules_dict)} YARA rule file(s)...")
            compiled_rules = yara.compile(filepaths=rules_dict)
            logger.info("✓ YARA rules compiled successfully")

            return compiled_rules

        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            return None

    def scan(self, file_data: bytes) -> List[Dict]:
        """
        Scan file data with YARA rules.

        Args:
            file_data: Raw file bytes to scan

        Returns:
            List of matched rules with metadata and matched strings
        """
        if not self.enabled or self.rules is None:
            logger.warning("YARA scanner not enabled or no rules compiled")
            return []

        if not isinstance(file_data, bytes):
            logger.error("Input must be bytes")
            return []

        try:
            matches = self.rules.match(data=file_data, timeout=30)
            results = []

            for match in matches:
                # Extract matched strings
                matched_strings = []
                for string in match.strings:
                    try:
                        # Get first instance sample (up to 100 bytes)
                        sample = None
                        if string.instances:
                            raw_sample = string.instances[0]
                            # Safely decode or represent as hex
                            try:
                                sample = raw_sample.decode('utf-8', errors='ignore')[:100]
                            except:
                                sample = raw_sample.hex()[:100]

                        matched_strings.append({
                            "identifier": string.identifier,
                            "instances": len(string.instances),
                            "sample": sample
                        })
                    except Exception as e:
                        logger.debug(f"Error processing string match: {e}")
                        continue

                # Build result object
                result = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags) if match.tags else [],
                    "meta": dict(match.meta) if match.meta else {},
                    "strings": matched_strings,
                    "match_count": len(matched_strings)
                }

                results.append(result)
                logger.info(f"YARA match: {match.rule}")

            return results

        except yara.TimeoutError:
            logger.error("YARA scan timeout (30s exceeded)")
            return []
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return []

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a file by path.

        Args:
            file_path: Path to file to scan

        Returns:
            List of matched rules
        """
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                return []

            if not file_path.is_file():
                logger.error(f"Not a file: {file_path}")
                return []

            # Check file size (max 10MB for safety)
            file_size = file_path.stat().st_size
            max_size = 10 * 1024 * 1024  # 10MB
            
            if file_size > max_size:
                logger.warning(f"File too large ({file_size} bytes), max {max_size}")
                return []

            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            return self.scan(file_data)

        except PermissionError:
            logger.error(f"Permission denied reading file: {file_path}")
            return []
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return []

    def scan_string(self, code: str) -> List[Dict]:
        """
        Scan a code string.

        Args:
            code: Source code string

        Returns:
            List of matched rules
        """
        try:
            file_data = code.encode('utf-8')
            return self.scan(file_data)
        except Exception as e:
            logger.error(f"Error scanning string: {e}")
            return []

    def get_severity_score(self, matches: List[Dict]) -> int:
        """
        Calculate severity score based on matched rules.

        Args:
            matches: List of YARA rule matches

        Returns:
            Severity score (0-100)
        """
        if not matches:
            return 0

        severity_map = {
            "critical": 30,
            "high": 20,
            "medium": 10,
            "low": 5,
        }

        total_score = 0
        for match in matches:
            severity = match.get("meta", {}).get("severity", "medium")
            score = severity_map.get(severity.lower(), 10)
            total_score += score

        return min(100, total_score)

    def is_enabled(self) -> bool:
        """Check if YARA scanner is enabled and ready."""
        return self.enabled and self.rules is not None


if __name__ == "__main__":
    # Test the scanner
    print("\n" + "="*60)
    print("ShadowHunter AI - YARA Scanner Test")
    print("="*60)

    scanner = YaraScanner()

    if not scanner.is_enabled():
        print("\n✗ YARA scanner not available")
        print("Install with: pip install yara-python")
        exit(1)

    # Test with sample malicious code
    test_code = """
import ctypes
import os
import numpy as np

# AI generated malware sample
# CRYSTALS-Kyber quantum encryption
def quantum_encrypt(data):
    seed = os.urandom(32)
    np.random.seed(int.from_bytes(seed, 'big'))
    return encrypted_data

# NtAllocateVirtualMemory for memory allocation
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

def ghost_inject():
    NtAllocateVirtualMemory()
    WriteProcessMemory()

# AMSI bypass technique
def amsi_bypass():
    pass
"""

    print("\nScanning test sample...")
    matches = scanner.scan_string(test_code)

    if matches:
        print(f"\n✓ Detected {len(matches)} YARA rule match(es):\n")
        for match in matches:
            print(f"  Rule: {match['rule']}")
            meta = match.get('meta', {})
            if 'severity' in meta:
                print(f"  Severity: {meta['severity']}")
            if 'description' in meta:
                print(f"  Description: {meta['description']}")
            if 'llm_source' in meta:
                print(f"  LLM Source: {meta['llm_source']}")
            print(f"  Matched Strings: {match['match_count']}")
            print()

        severity = scanner.get_severity_score(matches)
        print(f"Overall Severity Score: {severity}/100")
    else:
        print("\n✗ No YARA matches found")

    print("\n" + "="*60)
