"""
ShadowHunter AI - YARA Scanner
Scans files using custom YARA rules for malware detection
"""

import yara
from pathlib import Path
from typing import List, Dict, Optional


class YaraScanner:
    """
    YARA-based malware scanner for AI-generated threats
    """

    def __init__(self, rules_dir: str = None):
        """
        Initialize YARA scanner with rules

        Args:
            rules_dir: Path to YARA rules directory
        """
        if rules_dir is None:
            # Default to yara_rules directory
            rules_dir = Path(__file__).parent / "yara_rules"
        else:
            rules_dir = Path(rules_dir)

        self.rules_dir = rules_dir
        self.rules = self._compile_rules()

    def _compile_rules(self) -> Optional[yara.Rules]:
        """
        Compile all YARA rules from directory

        Returns:
            Compiled YARA rules object
        """
        try:
            rule_files = list(self.rules_dir.glob("*.yar"))

            if not rule_files:
                print(f"Warning: No .yar files found in {self.rules_dir}")
                return None

            # Create rules dictionary for compilation
            rules_dict = {
                str(f.stem): str(f) for f in rule_files
            }

            print(f"Compiling {len(rules_dict)} YARA rule files...")
            compiled_rules = yara.compile(filepaths=rules_dict)
            print("YARA rules compiled successfully!")

            return compiled_rules

        except yara.SyntaxError as e:
            print(f"YARA syntax error: {e}")
            return None
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
            return None

    def scan(self, file_data: bytes) -> List[Dict]:
        """
        Scan file data with YARA rules

        Args:
            file_data: Raw file bytes to scan

        Returns:
            List of matched rules with metadata
        """
        if self.rules is None:
            return []

        try:
            matches = self.rules.match(data=file_data)
            results = []

            for match in matches:
                # Extract matched strings
                matched_strings = []
                for string in match.strings:
                    matched_strings.append({
                        "identifier": string.identifier,
                        "instances": len(string.instances),
                        "sample": string.instances[0] if string.instances else None
                    })

                # Build result object
                result = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": matched_strings
                }

                results.append(result)

            return results

        except Exception as e:
            print(f"YARA scan error: {e}")
            return []

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a file by path

        Args:
            file_path: Path to file to scan

        Returns:
            List of matched rules
        """
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            return self.scan(file_data)
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return []

    def get_severity_score(self, matches: List[Dict]) -> int:
        """
        Calculate severity score based on matched rules

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
            "low": 5
        }

        total_score = 0
        for match in matches:
            severity = match.get("meta", {}).get("severity", "medium")
            total_score += severity_map.get(severity, 10)

        return min(100, total_score)


# Standalone test
if __name__ == "__main__":
    scanner = YaraScanner()

    # Test with sample malicious code
    test_code = b"""
import ctypes
import os
import numpy as np

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
"""

    print("\nScanning test sample...")
    matches = scanner.scan(test_code)

    if matches:
        print(f"\nDetected {len(matches)} YARA rule matches:")
        for match in matches:
            print(f"\n  Rule: {match['rule']}")
            print(f"  Severity: {match['meta'].get('severity', 'N/A')}")
            print(f"  Description: {match['meta'].get('description', 'N/A')}")
            if 'llm_source' in match['meta']:
                print(f"  LLM Source: {match['meta']['llm_source']}")

        severity = scanner.get_severity_score(matches)
        print(f"\nOverall Severity Score: {severity}/100")
    else:
        print("\nNo YARA matches found.")
