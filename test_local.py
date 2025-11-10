#!/usr/bin/env python3
"""
Local Testing Script for ShadowHunter AI
Tests pattern detection on all sample files
"""

import sys
import os
from pathlib import Path

# Add analyzer to path
sys.path.insert(0, str(Path(__file__).parent / 'analyzer'))

from patterns import AICodePatternDetector

def test_sample(file_path: str, expected_detection: bool):
    """Test a single sample file"""
    print(f"\n{'='*60}")
    print(f"Testing: {file_path}")
    print(f"Expected: {'MALICIOUS' if expected_detection else 'CLEAN'}")
    print(f"{'='*60}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        detector = AICodePatternDetector()
        result = detector.analyze(code)
        
        # Print results
        print(f"\n🔍 Analysis Results:")
        print(f"  AI Generated: {result['is_ai_generated']}")
        print(f"  LLM Source: {result['llm_source']}")
        print(f"  Confidence: {result['confidence']:.2%}")
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Entropy: {result['entropy']}")
        print(f"  Obfuscation: {result['obfuscation_level']}")
        
        if result['detected_patterns']:
            print(f"\n  Detected Patterns:")
            for pattern in result['detected_patterns'][:5]:
                print(f"    - {pattern}")
        
        if result['evasion_techniques']:
            print(f"\n  Evasion Techniques:")
            for tech in result['evasion_techniques'][:5]:
                print(f"    - {tech}")
        
        if result['malicious_indicators']:
            print(f"\n  Malicious Functions:")
            for func in result['malicious_indicators'][:5]:
                print(f"    - {func}")
        
        # Verify result
        detected = result['is_ai_generated'] or result['risk_score'] > 30
        
        if detected == expected_detection:
            print(f"\n✅ PASS - Correct detection!")
            return True
        else:
            print(f"\n❌ FAIL - Detection mismatch!")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("\n🛡️  ShadowHunter AI - Local Test Suite")
    print("="*60)
    
    test_cases = [
        ("tests/samples/deepseek_generated_malware.py", True),
        ("tests/samples/gpt4_generated_malware.py", True),
        ("tests/samples/claude_generated_code.py", True),
        ("tests/samples/clean_sample.py", False),
    ]
    
    results = []
    for file_path, expected in test_cases:
        if os.path.exists(file_path):
            passed = test_sample(file_path, expected)
            results.append((file_path, passed))
        else:
            print(f"\n⚠️  File not found: {file_path}")
            results.append((file_path, False))
    
    # Summary
    print("\n\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, p in results if p)
    total = len(results)
    
    for file_path, passed_test in results:
        status = "✅ PASS" if passed_test else "❌ FAIL"
        print(f"{status} - {os.path.basename(file_path)}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print(f"Success Rate: {(passed/total)*100:.1f}%\n")
    
    if passed == total:
        print("🎉 All tests passed! Pattern detector working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Review the results above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
