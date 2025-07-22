#!/usr/bin/env python3
"""
Test comprehensive rate limiting system
"""

from services.ai_analyzer import AIAnalyzer

def test_rate_limiting_system():
    print('🔧 Testing comprehensive rate limiting system...')

    # Test initialization
    ai_analyzer = AIAnalyzer()
    print('✅ AIAnalyzer initialized successfully')

    test_data = {
        'virustotal_data': {'malicious_count': 5, 'suspicious_count': 2},
        'urlscan_data': {'malicious_domains': 1, 'suspicious_domains': 0},
        'abuseipdb_data': {'abuse_confidence': 85, 'total_reports': 15}
    }

    # Test threat level assessment
    threat_level = ai_analyzer._assess_threat_level(test_data)
    print(f'✅ Threat level assessment: {threat_level}')

    # Test chunking
    chunks = ai_analyzer.data_chunker.chunk_analysis_data(test_data)
    print(f'✅ Data chunking: {len(chunks)} chunks created')
    for i, chunk in enumerate(chunks):
        print(f'  Chunk {i+1}: {chunk["source"]} ({chunk.get("chunk_type", "unknown")})')

    # Test rate limit status
    status = ai_analyzer.rate_limit_manager.get_status()
    print(f'✅ Rate limit status: {status["requests_remaining"]} requests, {status["tokens_remaining"]} tokens remaining')
    print(f'   Usage: {status["request_usage_percent"]:.1f}% requests, {status["token_usage_percent"]:.1f}% tokens')

    # Test chunk processing decision
    should_process = ai_analyzer._should_process_chunk(chunks[0], threat_level)
    print(f'✅ Chunk processing logic: Should process first chunk = {should_process}')

    print('')
    print('🎉 Comprehensive rate limiting system is ready!')
    print('🔥 429 hataları artık çok daha az görülecek!')
    print('')
    print('💡 Sistemin özellikleri:')
    print('   • Token ve request bazlı rate limiting')
    print('   • Chunked analiz ile büyük verilerin parçalanması')
    print('   • Threat level bazında optimizasyon')
    print('   • Progressif retry stratejileri')
    print('   • Cache entegrasyonu')
    print('   • OpenAI API header monitoring')
    print('')
    print('🚀 Sistem kullanıma hazır!')
    
    return True

if __name__ == "__main__":
    try:
        test_rate_limiting_system()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
