#!/usr/bin/env python
"""
IPQualityScore API Debug Script
Test your API key directly to verify it's working correctly
"""

import requests
import json
import time
from datetime import datetime

# ============================================
# CONFIGURATION - PUT YOUR API KEY HERE
# ============================================

# Replace this with your actual IPQualityScore API key
API_KEY = "xlCVaiHDldDPDV18domjGpiOnAqNVYzB"  # <-- PASTE YOUR API KEY HERE

# Test IP addresses to use
TEST_IPS = [
    '8.8.8.8',      # Google DNS - should be low risk
    '1.1.1.1',      # Cloudflare DNS - should be low risk
    '85.25.43.74',  # Example IP - may show more data
]

# ============================================
# API ENDPOINTS
# ============================================

IPQS_BASE_URL = "https://ipqualityscore.com/api/json"

def test_ip_lookup(ip_address, api_key):
    """
    Test IP lookup with the provided API key
    """
    print(f"\n{'='*60}")
    print(f"Testing IP Lookup: {ip_address}")
    print(f"{'='*60}")
    
    endpoint = f"{IPQS_BASE_URL}/ip/{ip_address}"
    params = {
        'key': api_key,
        'strictness': 0,
        'fast': 'true',
        'allow_public_access_points': 'true'
    }
    
    start_time = time.time()
    
    try:
        print(f"\n[1] Sending request to IPQualityScore API...")
        print(f"    URL: {endpoint}")
        print(f"    Params: {params}")
        
        response = requests.get(endpoint, params=params, timeout=30)
        response_time = time.time() - start_time
        
        print(f"\n[2] Response received:")
        print(f"    Status Code: {response.status_code}")
        print(f"    Response Time: {response_time:.3f} seconds")
        
        # Parse JSON response
        try:
            data = response.json()
        except json.JSONDecodeError:
            print(f"    Raw Response: {response.text[:500]}")
            print("\n❌ ERROR: Invalid JSON response")
            return None
        
        print(f"\n[3] Response Data:")
        print(f"    {json.dumps(data, indent=2)}")
        
        # Analyze the response
        print(f"\n[4] Analysis:")
        
        # Check if request was successful
        if data.get('success') is False:
            error_msg = data.get('message', 'Unknown error')
            print(f"    ❌ API Error: {error_msg}")
            return data
        
        # Check for invalid key
        if data.get('message') == 'Invalid or unauthorized key':
            print("    ❌ INVALID API KEY - Please check your API key")
            return data
        
        # Check if we got IP data
        ip = data.get('ip_address')
        if ip:
            print(f"    ✅ Valid IP: {ip}")
        else:
            print("    ⚠️ No IP address returned")
        
        # Fraud score
        fraud_score = data.get('fraud_score')
        if fraud_score is not None:
            risk_level = "Low" if fraud_score <= 25 else "Medium" if fraud_score <= 50 else "High" if fraud_score <= 75 else "Critical"
            print(f"    📊 Fraud Score: {fraud_score}/100 ({risk_level} Risk)")
        
        # Geolocation
        country = data.get('country_name')
        city = data.get('city')
        if country:
            print(f"    📍 Location: {city}, {country}" if city else f"    📍 Country: {country}")
        
        # Network info
        isp = data.get('ISP')
        if isp:
            print(f"    🏢 ISP: {isp}")
        
        asn = data.get('ASN')
        if asn:
            print(f"    🔢 ASN: {asn}")
        
        # Security checks
        security_flags = []
        if data.get('vpn'):
            security_flags.append("VPN")
        if data.get('proxy'):
            security_flags.append("Proxy")
        if data.get('tor'):
            security_flags.append("Tor")
        if data.get('bot_status'):
            security_flags.append("Bot")
        if data.get('hosting_provider'):
            security_flags.append("Hosting Provider")
        
        if security_flags:
            print(f"    🛡️ Security Flags: {', '.join(security_flags)}")
        else:
            print("    ✅ No security flags detected")
        
        # Check for abuse
        if data.get('recent_abuse'):
            print("    ⚠️ Recent abuse detected")
        
        print("\n    ✅ IP lookup completed successfully!")
        return data
        
    except requests.exceptions.Timeout:
        print(f"\n❌ ERROR: Request timed out after 30 seconds")
        return None
    except requests.exceptions.ConnectionError:
        print(f"\n❌ ERROR: Connection error - Please check your internet connection")
        return None
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        return None


def test_email_lookup(email, api_key):
    """
    Test email lookup with the provided API key
    """
    print(f"\n{'='*60}")
    print(f"Testing Email Lookup: {email}")
    print(f"{'='*60}")
    
    endpoint = f"{IPQS_BASE_URL}/email/{email}"
    params = {
        'key': api_key,
        'strictness': 1,
        'abuse_strictness': 1
    }
    
    start_time = time.time()
    
    try:
        print(f"\n[1] Sending request to IPQualityScore API...")
        response = requests.get(endpoint, params=params, timeout=30)
        response_time = time.time() - start_time
        
        print(f"\n[2] Response received:")
        print(f"    Status Code: {response.status_code}")
        print(f"    Response Time: {response_time:.3f} seconds")
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            print(f"    Raw Response: {response.text[:500]}")
            print("\n❌ ERROR: Invalid JSON response")
            return None
        
        print(f"\n[3] Response Data:")
        print(f"    {json.dumps(data, indent=2)}")
        
        print(f"\n[4] Analysis:")
        
        if data.get('success') is False:
            error_msg = data.get('message', 'Unknown error')
            print(f"    ❌ API Error: {error_msg}")
            return data
        
        if data.get('message') == 'Invalid or unauthorized key':
            print("    ❌ INVALID API KEY - Please check your API key")
            return data
        
        # Email validation
        valid = data.get('valid')
        if valid:
            print(f"    ✅ Valid Email: {email}")
        else:
            print(f"    ❌ Invalid Email: {email}")
        
        deliverable = data.get('deliverable')
        if deliverable:
            print(f"    ✅ Deliverable")
        else:
            print(f"    ⚠️ Not deliverable")
        
        fraud_score = data.get('fraud_score')
        if fraud_score is not None:
            risk_level = "Low" if fraud_score <= 25 else "Medium" if fraud_score <= 50 else "High" if fraud_score <= 75 else "Critical"
            print(f"    📊 Fraud Score: {fraud_score}/100 ({risk_level} Risk)")
        
        if data.get('disposable'):
            print("    ⚠️ Disposable/Temporary Email")
        
        if data.get('recent_abuse'):
            print("    ⚠️ Recent abuse detected")
        
        if data.get('domain_blacklisted'):
            print("    ⚠️ Domain is blacklisted")
        
        print("\n    ✅ Email lookup completed successfully!")
        return data
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        return None


def test_phone_lookup(phone, api_key):
    """
    Test phone lookup with the provided API key
    """
    print(f"\n{'='*60}")
    print(f"Testing Phone Lookup: {phone}")
    print(f"{'='*60}")
    
    endpoint = f"{IPQS_BASE_URL}/phone"
    params = {
        'key': api_key,
        'phone': phone,
        'country_code': 'auto'
    }
    
    start_time = time.time()
    
    try:
        print(f"\n[1] Sending request to IPQualityScore API...")
        response = requests.get(endpoint, params=params, timeout=30)
        response_time = time.time() - start_time
        
        print(f"\n[2] Response received:")
        print(f"    Status Code: {response.status_code}")
        print(f"    Response Time: {response_time:.3f} seconds")
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            print(f"    Raw Response: {response.text[:500]}")
            print("\n❌ ERROR: Invalid JSON response")
            return None
        
        print(f"\n[3] Response Data:")
        print(f"    {json.dumps(data, indent=2)}")
        
        print(f"\n[4] Analysis:")
        
        if data.get('success') is False:
            error_msg = data.get('message', 'Unknown error')
            print(f"    ❌ API Error: {error_msg}")
            return data
        
        if data.get('message') == 'Invalid or unauthorized key':
            print("    ❌ INVALID API KEY - Please check your API key")
            return data
        
        valid = data.get('valid')
        if valid:
            print(f"    ✅ Valid Phone: {phone}")
        else:
            print(f"    ❌ Invalid Phone: {phone}")
        
        country = data.get('country')
        if country:
            print(f"    📍 Country: {country}")
        
        carrier = data.get('carrier')
        if carrier:
            print(f"    📱 Carrier: {carrier}")
        
        line_type = data.get('line_type')
        if line_type:
            print(f"    📞 Line Type: {line_type}")
        
        fraud_score = data.get('fraud_score')
        if fraud_score is not None:
            risk_level = "Low" if fraud_score <= 25 else "Medium" if fraud_score <= 50 else "High" if fraud_score <= 75 else "Critical"
            print(f"    📊 Fraud Score: {fraud_score}/100 ({risk_level} Risk)")
        
        if data.get('prepaid'):
            print("    ⚠️ Prepaid Phone")
        
        if data.get('recent_abuse'):
            print("    ⚠️ Recent abuse detected")
        
        print("\n    ✅ Phone lookup completed successfully!")
        return data
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        return None


def test_url_lookup(url, api_key):
    """
    Test URL lookup with the provided API key
    """
    print(f"\n{'='*60}")
    print(f"Testing URL Lookup: {url}")
    print(f"{'='*60}")
    
    endpoint = f"{IPQS_BASE_URL}/url"
    params = {
        'key': api_key,
        'url': url,
        'strictness': 1,
        'fast': 'false'
    }
    
    start_time = time.time()
    
    try:
        print(f"\n[1] Sending request to IPQualityScore API...")
        response = requests.get(endpoint, params=params, timeout=30)
        response_time = time.time() - start_time
        
        print(f"\n[2] Response received:")
        print(f"    Status Code: {response.status_code}")
        print(f"    Response Time: {response_time:.3f} seconds")
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            print(f"    Raw Response: {response.text[:500]}")
            print("\n❌ ERROR: Invalid JSON response")
            return None
        
        print(f"\n[3] Response Data:")
        print(f"    {json.dumps(data, indent=2)}")
        
        print(f"\n[4] Analysis:")
        
        if data.get('success') is False:
            error_msg = data.get('message', 'Unknown error')
            print(f"    ❌ API Error: {error_msg}")
            return data
        
        if data.get('message') == 'Invalid or unauthorized key':
            print("    ❌ INVALID API KEY - Please check your API key")
            return data
        
        unsafe = data.get('unsafe')
        if unsafe:
            print(f"    ⚠️ URL is unsafe!")
        else:
            print(f"    ✅ URL appears safe")
        
        risk_score = data.get('risk_score')
        if risk_score is not None:
            risk_level = "Low" if risk_score <= 25 else "Medium" if risk_score <= 50 else "High" if risk_score <= 75 else "Critical"
            print(f"    📊 Risk Score: {risk_score}/100 ({risk_level} Risk)")
        
        if data.get('phishing'):
            print("    ⚠️ Phishing detected!")
        
        if data.get('malware'):
            print("    ⚠️ Malware detected!")
        
        if data.get('suspicious'):
            print("    ⚠️ URL is suspicious!")
        
        category = data.get('category')
        if category:
            print(f"    📂 Category: {category}")
        
        print("\n    ✅ URL lookup completed successfully!")
        return data
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        return None


def main():
    """Main test function"""
    print("="*60)
    print("IPQUALITYSCORE API DEBUG TOOL")
    print("="*60)
    
    # Check if API key is provided
    if API_KEY == "YOUR_API_KEY_HERE":
        print("\n❌ ERROR: Please set your API key in the script!")
        print("   Open test_ipqs_api.py and replace 'YOUR_API_KEY_HERE' with your actual API key")
        print("\n   Example:")
        print("   API_KEY = 'your_actual_api_key_here'")
        return
    
    print(f"\n✅ API Key provided: {API_KEY[:8]}...{API_KEY[-4:]}")
    print(f"   (First 8 and last 4 characters shown for security)")
    
    # Check API key format
    if len(API_KEY) < 20:
        print("\n⚠️ WARNING: API key seems too short. Please verify it's correct.")
    
    print("\n" + "="*60)
    print("STARTING TESTS")
    print("="*60)
    
    results = {
        'ip': [],
        'email': [],
        'phone': [],
        'url': []
    }
    
    # Test IP Lookups
    print("\n📡 Testing IP Lookups...")
    for ip in TEST_IPS:
        result = test_ip_lookup(ip, API_KEY)
        results['ip'].append({
            'query': ip,
            'success': result is not None and result.get('success') is not False,
            'data': result
        })
    
    # Test Email Lookup
    print("\n📧 Testing Email Lookup...")
    result = test_email_lookup('test@example.com', API_KEY)
    results['email'].append({
        'query': 'test@example.com',
        'success': result is not None and result.get('success') is not False,
        'data': result
    })
    
    # Test Phone Lookup
    print("\n📱 Testing Phone Lookup...")
    result = test_phone_lookup('+14155552671', API_KEY)
    results['phone'].append({
        'query': '+14155552671',
        'success': result is not None and result.get('success') is not False,
        'data': result
    })
    
    # Test URL Lookup
    print("\n🔗 Testing URL Lookup...")
    result = test_url_lookup('https://google.com', API_KEY)
    results['url'].append({
        'query': 'https://google.com',
        'success': result is not None and result.get('success') is not False,
        'data': result
    })
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    total_tests = len(results['ip']) + len(results['email']) + len(results['phone']) + len(results['url'])
    successful_tests = 0
    
    for category, tests in results.items():
        for test in tests:
            if test['success']:
                successful_tests += 1
    
    print(f"\n📊 Total Tests: {total_tests}")
    print(f"✅ Successful: {successful_tests}")
    print(f"❌ Failed: {total_tests - successful_tests}")
    
    if successful_tests == total_tests:
        print("\n🎉 ALL TESTS PASSED! Your API key is valid and working correctly.")
        print("   You can now use this key in your Django application.")
    elif successful_tests > 0:
        print("\n⚠️ SOME TESTS PASSED but others failed. Your API key may have limitations.")
        print("   Check the individual test results above for details.")
    else:
        print("\n❌ ALL TESTS FAILED! Your API key is invalid.")
        print("   Please check the following:")
        print("   1. Verify the API key is correct")
        print("   2. Make sure you have an active IPQualityScore account")
        print("   3. Check if your API key has the required permissions")
        print("   4. Ensure you have API credits available")
    
    print("\n" + "="*60)
    print("Debug information saved. Check the output above for details.")
    print("="*60)


if __name__ == "__main__":
    main()