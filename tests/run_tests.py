#!/usr/bin/env python3
"""
Test Runner for Secure Trading Platform
Runs all test suites in sequence
"""

import unittest
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

def run_test_suite(suite_name, test_class):
    """Run a specific test suite"""
    print(f"\n{'='*60}")
    print(f"Running {suite_name}")
    print('='*60)
    
    try:
        # Create a test suite with the test class
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return result.wasSuccessful()
    except Exception as e:
        print(f"Error running {suite_name}: {str(e)}")
        return False

def main():
    """Run all test suites"""
    print("Secure Trading Platform - Test Runner")
    print("=====================================")
    
    # Import test modules
    try:
        from tests.test_suite import TestSecureTradingPlatform
        from tests.comprehensive_test_suite import TestSecureTradingPlatform as ComprehensiveTest
        from tests.security_test_suite import TestSecurityComponents
        from tests.api_test_suite import TestAPIEndpoints
    except ImportError as e:
        print(f"Error importing test modules: {str(e)}")
        return 1
    
    # Run test suites in order
    test_suites = [
        ("Basic Test Suite", TestSecureTradingPlatform),
        ("Comprehensive Test Suite", ComprehensiveTest),
        ("Security Components Test Suite", TestSecurityComponents),
        ("API Endpoints Test Suite", TestAPIEndpoints)
    ]
    
    results = []
    for suite_name, test_class in test_suites:
        success = run_test_suite(suite_name, test_class)
        results.append((suite_name, success))
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    all_passed = True
    for suite_name, success in results:
        status = "PASSED" if success else "FAILED"
        print(f"{suite_name}: {status}")
        if not success:
            all_passed = False
    
    print("="*60)
    if all_passed:
        print("ALL TESTS PASSED!")
        return 0
    else:
        print("SOME TESTS FAILED!")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)