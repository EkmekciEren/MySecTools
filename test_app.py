#!/usr/bin/env python3
"""
Test script for the Security Analysis Application
Siber Güvenlik Analiz Uygulaması için test scripti
"""

import requests
import json
import sys
import time
from urllib.parse import urlencode

# Test configuration
BASE_URL = "http://localhost:5000"
TEST_TARGETS = [
    "google.com",           # Safe domain
    "8.8.8.8",             # Google DNS
    "https://example.com",  # Safe URL
    "microsoft.com",        # Safe domain
]

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*60)
    print(f"🔍 {title}")
    print("="*60)

def print_result(target, success, message, data=None):
    """Print test result"""
    status = "✅ BAŞARILI" if success else "❌ HATA"
    print(f"\n{status} - {target}")
    print(f"Mesaj: {message}")
    
    if data and success:
        summary = data.get('analysis_summary', {})
        print(f"Risk Seviyesi: {summary.get('risk_level', 'Bilinmiyor')}")
        print(f"Tehdit Tespit Edildi: {'Evet' if summary.get('threats_detected') else 'Hayır'}")
        print(f"Kullanılan Kaynaklar: {', '.join(summary.get('data_sources_used', []))}")

def test_health_endpoint():
    """Test health check endpoint"""
    print_header("Health Check Testi")
    
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Health check başarılı")
            print(f"Status: {data.get('status')}")
            print(f"Message: {data.get('message')}")
            return True
        else:
            print(f"❌ Health check başarısız: {response.status_code}")
            return False
            
    except requests.RequestException as e:
        print(f"❌ Bağlantı hatası: {e}")
        return False

def test_analyze_endpoint(target):
    """Test analyze endpoint with a target"""
    try:
        params = {'target': target}
        url = f"{BASE_URL}/analyze?" + urlencode(params)
        
        print(f"\n🔍 Analiz ediliyor: {target}")
        print(f"URL: {url}")
        
        start_time = time.time()
        response = requests.get(url, timeout=120)  # 2 minute timeout
        end_time = time.time()
        
        duration = end_time - start_time
        print(f"⏱️  Süre: {duration:.2f} saniye")
        
        if response.status_code == 200:
            data = response.json()
            print_result(target, True, "Analiz başarıyla tamamlandı", data)
            return True, data
        else:
            error_data = response.json() if response.headers.get('content-type') == 'application/json' else {'error': response.text}
            print_result(target, False, f"HTTP {response.status_code}: {error_data.get('error', 'Bilinmeyen hata')}")
            return False, error_data
            
    except requests.Timeout:
        print_result(target, False, "Zaman aşımı - Analiz 2 dakikada tamamlanamadı")
        return False, None
    except requests.RequestException as e:
        print_result(target, False, f"Bağlantı hatası: {e}")
        return False, None

def test_invalid_targets():
    """Test invalid target validation"""
    print_header("Geçersiz Hedef Testi")
    
    invalid_targets = [
        "",                    # Empty string
        "localhost",          # Localhost
        "127.0.0.1",         # Localhost IP
        "192.168.1.1",       # Private IP
        "invalid..domain",    # Invalid domain
        "javascript:alert(1)", # Malicious input
    ]
    
    for target in invalid_targets:
        success, _ = test_analyze_endpoint(target)
        if success:
            print(f"⚠️  UYARI: Geçersiz hedef kabul edildi: {target}")

def save_test_results(results):
    """Save test results to file"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"test_results_{timestamp}.json"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(f"\n💾 Test sonuçları kaydedildi: {filename}")
    except Exception as e:
        print(f"\n❌ Test sonuçları kaydedilemedi: {e}")

def main():
    """Main test function"""
    print_header("Siber Güvenlik Analiz Uygulaması - Test Scripti")
    
    # Check if server is running
    if not test_health_endpoint():
        print("\n❌ Sunucu çalışmıyor. Lütfen önce 'python app.py' ile uygulamayı başlatın.")
        sys.exit(1)
    
    results = {
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'tests': []
    }
    
    # Test valid targets
    print_header("Geçerli Hedef Testleri")
    for target in TEST_TARGETS:
        success, data = test_analyze_endpoint(target)
        results['tests'].append({
            'target': target,
            'success': success,
            'data': data
        })
        
        # Small delay between requests to avoid rate limiting
        time.sleep(2)
    
    # Test invalid targets
    test_invalid_targets()
    
    # Summary
    successful_tests = sum(1 for test in results['tests'] if test['success'])
    total_tests = len(results['tests'])
    
    print_header("Test Özeti")
    print(f"Toplam Test: {total_tests}")
    print(f"Başarılı: {successful_tests}")
    print(f"Başarısız: {total_tests - successful_tests}")
    print(f"Başarı Oranı: {(successful_tests/total_tests)*100:.1f}%")
    
    # Save results
    save_test_results(results)
    
    if successful_tests == total_tests:
        print("\n🎉 Tüm testler başarıyla tamamlandı!")
        return 0
    else:
        print(f"\n⚠️  {total_tests - successful_tests} test başarısız oldu.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⏹️  Test scripti kullanıcı tarafından durduruldu.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Beklenmeyen hata: {e}")
        sys.exit(1)
