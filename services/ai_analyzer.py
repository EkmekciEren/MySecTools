import os
import logging
from typing import Dict, Any, List
import json
import time
import random
from utils.cache_manager import CacheManager
from utils.rate_limit_manager import OpenAIRateLimitManager
from utils.data_chunker import DataChunker
from utils.enhanced_rule_analyzer import EnhancedRuleBasedAnalyzer

logger = logging.getLogger(__name__)

class AIAnalyzer:
    """AI-powered security analysis using OpenAI GPT-4o"""
    
    def __init__(self, api_key=None):
        """
        Initialize AI Analyzer
        
        Args:
            api_key: Custom OpenAI API key to use instead of environment variable
        """
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.model = os.getenv('AI_MODEL', 'gpt-4o')
        self.max_tokens = int(os.getenv('AI_MAX_TOKENS', '2000'))
        self.temperature = float(os.getenv('AI_TEMPERATURE', '0.3'))
        
        # Rate limiting configuration
        self.max_retries = int(os.getenv('AI_MAX_RETRIES', '3'))
        self.base_delay = float(os.getenv('AI_BASE_DELAY', '1.0'))
        self.max_delay = float(os.getenv('AI_MAX_DELAY', '30.0'))
        self.request_timeout = float(os.getenv('AI_REQUEST_TIMEOUT', '30.0'))
        
        # Cache configuration
        cache_ttl = int(os.getenv('AI_CACHE_TTL', '3600'))  # 1 hour default
        self.cache_manager = CacheManager(ttl_seconds=cache_ttl)
        
        # Rate limit manager
        self.rate_limit_manager = OpenAIRateLimitManager(self.api_key)
        
        # Data chunker for large requests
        self.data_chunker = DataChunker()
        
        # Enhanced rule-based analyzer for fallback
        self.enhanced_rule_analyzer = EnhancedRuleBasedAnalyzer()
        
        # Initialize OpenAI client if available
        self.client = None
        if self.api_key and self.api_key != 'your_openai_api_key_here':
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=self.api_key,
                    timeout=self.request_timeout
                )
                # Test quota on initialization (async, don't block startup)
                self._test_quota_async()
            except ImportError:
                logger.error("OpenAI library not installed")
    
    def _test_quota_async(self):
        """Test quota asynchronously without blocking initialization"""
        try:
            # Try a minimal request to check quota
            test_response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=1,
                temperature=0
            )
            logger.debug("✅ OpenAI quota test passed")
        except Exception as e:
            error_str = str(e).lower()
            if 'quota' in error_str or 'insufficient_quota' in error_str:
                self.rate_limit_manager.rate_limit.quota_exceeded = True
                logger.warning("🚨 OpenAI quota exceeded detected on startup - rule-based analysis will be used")
            else:
                logger.debug(f"Quota test failed with: {str(e)}")
    
    def _make_openai_request(self, messages, max_tokens=None, temperature=None):
        """
        Make OpenAI API request with comprehensive rate limiting
        
        Args:
            messages: List of messages for the chat completion
            max_tokens: Maximum tokens for response
            temperature: Temperature for response generation
            
        Returns:
            OpenAI response object
            
        Raises:
            Exception: If all retries fail
        """
        # Early exit if quota exceeded
        if self.rate_limit_manager.rate_limit.quota_exceeded:
            raise Exception("insufficient_quota: Quota exceeded, using rule-based analysis")
        
        if not self.client:
            raise Exception("OpenAI client not initialized")
        
        max_tokens = max_tokens or self.max_tokens
        temperature = temperature or self.temperature
        
        # Estimate total tokens for request
        request_text = json.dumps(messages, ensure_ascii=False)
        estimated_request_tokens = self.data_chunker.estimate_tokens(request_text)
        estimated_total_tokens = estimated_request_tokens + max_tokens
        
        # Check rate limits before making request
        if not self.rate_limit_manager.wait_if_needed(estimated_total_tokens):
            raise Exception("Rate limit exceeded and cannot proceed")
        
        for attempt in range(self.max_retries + 1):  # +1 for initial attempt
            try:
                # Double-check rate limits just before request
                can_proceed, reason, wait_seconds = self.rate_limit_manager.can_make_request(estimated_total_tokens)
                if not can_proceed:
                    if wait_seconds > 0:
                        logger.warning(f"Last-minute rate limit hit: {reason}, waiting {wait_seconds}s")
                        time.sleep(wait_seconds + 1)
                    else:
                        raise Exception(f"Rate limit exceeded: {reason}")
                
                logger.debug(f"OpenAI API request attempt {attempt + 1}/{self.max_retries + 1}")
                logger.debug(f"Estimated tokens: {estimated_total_tokens}")
                
                # Make the actual request
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature
                )
                
                # Update rate limits from response headers if available
                if hasattr(response, '_response') and hasattr(response._response, 'headers'):
                    self.rate_limit_manager.update_from_headers(dict(response._response.headers))
                
                # Record successful request
                actual_tokens = getattr(response.usage, 'total_tokens', estimated_total_tokens) if hasattr(response, 'usage') else estimated_total_tokens
                self.rate_limit_manager.record_request(actual_tokens)
                
                logger.debug(f"OpenAI API request successful, tokens used: {actual_tokens}")
                return response
                
            except Exception as e:
                error_str = str(e).lower()
                
                # Check if it's a rate limit error
                if '429' in error_str or 'quota' in error_str or 'rate limit' in error_str:
                    # Check for quota exhaustion (permanent failure)
                    if 'insufficient_quota' in error_str or 'exceeded your current quota' in error_str:
                        self.rate_limit_manager.rate_limit.quota_exceeded = True
                        logger.error("🚨 OpenAI quota exceeded - switching to rule-based analysis permanently")
                        raise e  # Re-raise to trigger fallback
                    
                    # Regular rate limiting - retry with backoff
                    if attempt < self.max_retries:
                        # Progressive backoff with rate limit awareness
                        base_delay = self.base_delay * (2 ** attempt)
                        jitter = random.uniform(0, 1)
                        
                        # If we know we're hitting rate limits, wait longer
                        if 'quota' in error_str:
                            # Quota exhausted - wait longer
                            delay = min(base_delay * 3 + jitter, self.max_delay)
                        else:
                            # Regular rate limit - shorter wait
                            delay = min(base_delay + jitter, self.max_delay)
                        
                        logger.warning(f"Rate limit hit, retrying in {delay:.2f} seconds (attempt {attempt + 1})")
                        time.sleep(delay)
                        continue
                    else:
                        logger.error("All retry attempts exhausted for rate limit error")
                        raise e
                
                # For non-rate-limit errors, don't retry
                logger.error(f"OpenAI API error: {str(e)}")
                raise e
        
        raise Exception("Maximum retry attempts reached")

    def _assess_threat_level(self, analysis_data: Dict[str, Any]) -> str:
        """
        Assess overall threat level from analysis data
        
        Returns:
            'HIGH', 'MEDIUM', or 'LOW'
        """
        threat_score = 0
        
        # URLScan threats
        urlscan = analysis_data.get('urlscan_data', {})
        if urlscan and 'error' not in urlscan:
            malicious = urlscan.get('malicious_domains', 0)
            suspicious = urlscan.get('suspicious_domains', 0)
            threat_score += malicious * 3 + suspicious * 1
        
        # VirusTotal threats
        vt = analysis_data.get('virustotal_data', {})
        if vt and 'error' not in vt:
            malicious = vt.get('malicious_count', 0)
            suspicious = vt.get('suspicious_count', 0)
            threat_score += malicious * 2 + suspicious * 1
        
        # AbuseIPDB threats
        abuse = analysis_data.get('abuseipdb_data', {})
        if abuse and 'error' not in abuse:
            confidence = abuse.get('abuse_confidence', 0)
            if confidence > 75:
                threat_score += 3
            elif confidence > 50:
                threat_score += 2
            elif confidence > 25:
                threat_score += 1
        
        if threat_score >= 5:
            return 'HIGH'
        elif threat_score >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _source_has_threats(self, source: str, data: dict) -> bool:
        """Check if a data source has any threats worth AI analysis"""
        if source == 'urlscan_data':
            return data.get('malicious_domains', 0) > 0 or data.get('suspicious_domains', 0) > 0
        elif source == 'virustotal_data':
            return data.get('malicious_count', 0) > 0 or data.get('suspicious_count', 0) > 0
        elif source == 'abuseipdb_data':
            return data.get('abuse_confidence', 0) > 25
        return False

    def analyze_step_by_step(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate step-by-step AI analysis of security data with chunking support
        
        Args:
            target: The analyzed target
            analysis_data: Combined data from all security APIs
            
        Returns:
            Dictionary with individual analyses and final summary
        """
        # Rate limit durumunu kontrol et - Free tier için daha agresif threshold
        rate_status = self.rate_limit_manager.get_status()
        
        # Free tier için %85 threshold (daha agresif)
        if (rate_status.get('request_usage_percent', 0) > 85 or 
            rate_status.get('token_usage_percent', 0) > 85):
            logger.info(f"High rate limit usage detected (free tier), using chunked analysis for {target}")
            return self.analyze_with_chunking(target, analysis_data)
        
        # Normal step-by-step analiz
        return self._analyze_step_by_step_normal(target, analysis_data)
    
    def _analyze_step_by_step_normal(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normal step-by-step analiz (eski yöntem)"""
        # Check cache first
        cached_result = self.cache_manager.get_cached_analysis(target, analysis_data)
        if cached_result:
            logger.info(f"Returning cached analysis for target: {target}")
            return cached_result
        
        # Check if quota is exceeded (early exit)
        if self.rate_limit_manager.rate_limit.quota_exceeded:
            logger.warning("OpenAI quota exceeded - using rule-based analysis")
            fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
            fallback_result['ai_error_message'] = "⚠️ OpenAI quota aşıldı. Kural tabanlı analiz kullanılıyor..."
            self.cache_manager.save_analysis_to_cache(target, analysis_data, fallback_result)
            return fallback_result
        
        if not self.client:
            fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
            fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: API anahtarı yapılandırılmamış. Kural tabanlı analiz uygulanıyor..."
            return fallback_result
        
        # Quick quota test before starting analysis
        try:
            # Make a minimal test request first to check quota
            test_response = self._make_openai_request([
                {"role": "user", "content": "test"}
            ], max_tokens=1, temperature=0)
            logger.debug("Quota test passed, proceeding with analysis")
        except Exception as e:
            error_str = str(e).lower()
            if 'quota' in error_str or 'insufficient_quota' in error_str:
                self.rate_limit_manager.rate_limit.quota_exceeded = True
                logger.error("🚨 Quota exceeded detected in test request - switching to rule-based analysis")
                fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
                fallback_result['ai_error_message'] = "⚠️ OpenAI quota aşıldı. Kural tabanlı analiz kullanılıyor..."
                self.cache_manager.save_analysis_to_cache(target, analysis_data, fallback_result)
                return fallback_result
            # For other errors, continue with normal flow
            logger.warning(f"Quota test failed with non-quota error: {str(e)}")
        
        try:
            # First, check if we need AI analysis or if rule-based is sufficient
            threat_level = self._assess_threat_level(analysis_data)
            
            # For low threat levels, use rule-based analysis to save API quota
            if threat_level == 'LOW' and os.getenv('AI_CONSERVATIVE_MODE', 'true').lower() == 'true':
                logger.info("Using rule-based analysis for low-threat target to conserve API quota")
                fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
                fallback_result['ai_error_message'] = "ℹ️ API kotası korunması için kural tabanlı analiz kullanıldı (düşük risk tespit edildi)"
                
                # Cache the result
                self.cache_manager.save_analysis_to_cache(target, analysis_data, fallback_result)
                return fallback_result
            
            step_analyses = {}
            data_sources = ['urlscan_data', 'virustotal_data', 'abuseipdb_data']
            
            # Step 1: Analyze each data source individually - only if they have threats
            for source in data_sources:
                if source in analysis_data and analysis_data[source] and 'error' not in analysis_data[source]:
                    # Check if this source has any threats worth AI analysis
                    if self._source_has_threats(source, analysis_data[source]):
                        step_analyses[source] = self._analyze_single_source(source, analysis_data[source])
                    else:
                        # Use rule-based for clean sources
                        step_analyses[source] = self._generate_step_fallback_analysis(source, analysis_data[source], "clean_source")
                else:
                    step_analyses[source] = f"{source.replace('_data', '').title()} verisi mevcut değil veya hatalı."
            
            # Step 2: Generate comprehensive final analysis only if high/medium threat
            try:
                if threat_level in ['HIGH', 'MEDIUM']:
                    final_analysis = self._generate_final_comprehensive_analysis(target, analysis_data, step_analyses)
                    ai_error_message = None  # Success case
                else:
                    # Use rule-based for low threats
                    final_analysis = self._generate_fallback_comprehensive_analysis(analysis_data, "low_threat")
                    ai_error_message = "ℹ️ Düşük risk seviyesi nedeniyle kural tabanlı analiz kullanıldı"
            except Exception as final_error:
                logger.warning(f"Final comprehensive analysis failed: {str(final_error)}")
                final_analysis = self._generate_fallback_comprehensive_analysis(analysis_data, str(final_error))
                
                # Hata türüne göre kullanıcı dostu mesaj belirleme
                error_str = str(final_error).lower()
                if 'quota' in error_str or '429' in error_str:
                    ai_error_message = "⚠️ AI analiz yapılamadı: OpenAI API kotası aşıldı. Kural tabanlı analiz uygulanıyor..."
                elif 'timeout' in error_str:
                    ai_error_message = "⚠️ AI analiz yapılamadı: Bağlantı zaman aşımı. Kural tabanlı analiz uygulanıyor..."
                elif 'authentication' in error_str or 'unauthorized' in error_str:
                    ai_error_message = "⚠️ AI analiz yapılamadı: API anahtarı geçersiz. Kural tabanlı analiz uygulanıyor..."
                else:
                    ai_error_message = "⚠️ AI analiz yapılamadı: Teknik bir hata oluştu. Kural tabanlı analiz uygulanıyor..."
            
            result = {
                'step_by_step_analysis': step_analyses,
                'final_comprehensive_analysis': final_analysis,
                'analysis_method': 'ai_powered_step_by_step',
                'ai_error_message': ai_error_message,
                'threat_level': threat_level
            }
            
            # Cache the result
            self.cache_manager.save_analysis_to_cache(target, analysis_data, result)
            
            return result
            
        except Exception as e:
            logger.warning(f"AI step-by-step analysis error: {str(e)}")
            fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
            
            # Hata türüne göre kullanıcı dostu mesaj belirleme
            error_str = str(e).lower()
            if 'quota' in error_str or '429' in error_str:
                fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: OpenAI API kotası aşıldı. Kural tabanlı analiz uygulanıyor..."
            elif 'timeout' in error_str:
                fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: Bağlantı zaman aşımı. Kural tabanlı analiz uygulanıyor..."
            elif 'authentication' in error_str or 'unauthorized' in error_str:
                fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: API anahtarı geçersiz. Kural tabanlı analiz uygulanıyor..."
            else:
                fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: Teknik bir hata oluştu. Kural tabanlı analiz uygulanıyor..."
            
            # Cache fallback result too
            self.cache_manager.save_analysis_to_cache(target, analysis_data, fallback_result)
            return fallback_result

    def _analyze_single_source(self, source_name: str, data: dict) -> str:
        """Analyze data from a single source"""
        try:
            # Check if we're in demo mode or have API issues
            if os.getenv('DEMO_MODE', 'false').lower() == 'true':
                return self._generate_demo_analysis(source_name, data)
            
            # Create a focused prompt for this specific source
            prompt = f"""
            Siber güvenlik uzmanı olarak, {source_name} veri kaynağından gelen aşağıdaki analiz verilerini değerlendir:
            
            {json.dumps(data, indent=2, ensure_ascii=False)}
            
            Bu veriler hakkında:
            1. Tespit edilen risk unsurları
            2. Güvenlik değerlendirmesi
            3. Bu kaynağa özgü öneriler
            
            Kısa ve net bir analiz yap (maksimum 3-4 cümle):
            """
            
            response = self._make_openai_request([
                {"role": "system", "content": "Sen bir siber güvenlik uzmanısın. Teknik verileri analiz edip anlaşılır değerlendirmeler yapıyorsun."},
                {"role": "user", "content": prompt}
            ], max_tokens=300, temperature=0.3)
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            # If API fails, provide fallback analysis
            return self._generate_step_fallback_analysis(source_name, data, str(e))

    def _generate_final_comprehensive_analysis(self, target: str, analysis_data: Dict[str, Any], step_analyses: Dict[str, str]) -> str:
        """Generate final comprehensive analysis based on all step analyses"""
        try:
            # Combine all individual analyses
            combined_analyses = "\n\n".join([f"### {key.replace('_data', '').title()} Analizi:\n{analysis}" 
                                           for key, analysis in step_analyses.items()])
            
            # Get summary statistics
            summary_stats = self._get_analysis_summary_stats(analysis_data)
            
            prompt = f"""
Hedef: {target}

Aşağıdaki bireysel analizleri değerlendirdim:

{combined_analyses}

## Özet İstatistikler:
{json.dumps(summary_stats, indent=2, ensure_ascii=False)}

Tüm bu analizleri birleştirerek kapsamlı bir güvenlik değerlendirmesi yap:

1. **GENEL RİSK SEVİYESİ** (Kritik/Yüksek/Orta/Düşük/Minimal)

2. **ANA BULGULAR**
   - En önemli 3-5 bulguyu listele

3. **TEHDİT ANALİZİ**
   - Tespit edilen potansiyel tehditler
   - Risk faktörleri

4. **GÜVENİLİRLİK DEĞERLENDİRMESİ**
   - Veri kaynaklarının tutarlılığı
   - Analiz güvenilirliği

5. **ÖNERİLER**
   - Kullanıcıya özel öneriler
   - Alınması gereken önlemler

6. **SONUÇ**
   - Net bir sonuç ve önerilen eylem

Profesyonel, detaylı ve anlaşılır bir analiz sun. Türkçe olarak yaz.
"""
            
            response = self._make_openai_request([
                {
                    "role": "system",
                    "content": "Sen kıdemli bir siber güvenlik uzmanısın. Çeşitli kaynaklardan gelen güvenlik verilerini birleştirerek kapsamlı risk değerlendirmeleri yapıyorsun. Analizin profesyonel, objektif ve pratik olmalı."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ], max_tokens=self.max_tokens, temperature=self.temperature)
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.warning(f"Final comprehensive analysis error: {str(e)}")
            
            # Quota hatası gibi önemli hatalar için exception'ı yeniden at
            error_str = str(e).lower()
            if 'quota' in error_str or '429' in error_str or 'authentication' in error_str or 'unauthorized' in error_str:
                raise e  # Exception'ı yukarı at ki hata mesajı ayarlanabilsin
            
            # Diğer hatalar için fallback döndür
            return self._generate_fallback_comprehensive_analysis(analysis_data, str(e))

    def analyze_with_chunking(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze using chunk-based approach for better rate limit management
        
        Args:
            target: The analyzed target
            analysis_data: Combined data from all security APIs
            
        Returns:
            Dictionary with chunked analyses and final summary
        """
        # Check cache first
        cached_result = self.cache_manager.get_cached_analysis(target, analysis_data)
        if cached_result:
            logger.info(f"Returning cached analysis for target: {target}")
            return cached_result
        
        # Check if quota is exceeded (early exit)
        if self.rate_limit_manager.rate_limit.quota_exceeded:
            logger.warning("OpenAI quota exceeded - using rule-based analysis for chunked request")
            fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
            fallback_result['ai_error_message'] = "⚠️ OpenAI quota aşıldı. Kural tabanlı analiz kullanılıyor..."
            self.cache_manager.save_analysis_to_cache(target, analysis_data, fallback_result)
            return fallback_result
        
        if not self.client:
            fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
            fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: API anahtarı yapılandırılmamış. Kural tabanlı analiz uygulanıyor..."
            return fallback_result
        
        try:
            # Assess threat level
            threat_level = self._assess_threat_level(analysis_data)
            
            # For low threat levels in conservative mode, use rule-based analysis
            if threat_level == 'LOW' and os.getenv('AI_CONSERVATIVE_MODE', 'true').lower() == 'true':
                logger.info("Using rule-based analysis for low-threat target to conserve API quota")
                fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
                fallback_result['ai_error_message'] = "ℹ️ API kotası korunması için kural tabanlı analiz kullanıldı (düşük risk tespit edildi)"
                self.cache_manager.save_analysis_to_cache(target, analysis_data, fallback_result)
                return fallback_result
            
            # Create chunks from analysis data
            chunks = self.data_chunker.chunk_analysis_data(analysis_data)
            prompts = self.data_chunker.create_analysis_prompts(chunks, target)
            
            # Analyze each chunk
            chunk_results = {}
            successful_chunks = 0
            
            for i, (prompt, estimated_tokens) in enumerate(prompts):
                chunk_source = chunks[i]['source']
                
                try:
                    # Check if we should process this chunk
                    if not self._should_process_chunk(chunks[i], threat_level):
                        chunk_results[chunk_source] = self._generate_step_fallback_analysis(
                            chunk_source, chunks[i]['data'], "low_priority_skipped"
                        )
                        continue
                    
                    # Make chunked AI request
                    response = self._make_openai_request([
                        {"role": "system", "content": "Sen bir siber güvenlik uzmanısın. Kısa ve net analizler yapıyorsun."},
                        {"role": "user", "content": prompt}
                    ], max_tokens=300, temperature=0.3)  # Free tier için optimize edilmiş
                    
                    chunk_results[chunk_source] = response.choices[0].message.content.strip()
                    successful_chunks += 1
                    
                    # Small delay between chunks to be respectful
                    time.sleep(0.5)
                    
                except Exception as chunk_error:
                    logger.warning(f"Chunk analysis failed for {chunk_source}: {str(chunk_error)}")
                    chunk_results[chunk_source] = self._generate_step_fallback_analysis(
                        chunk_source, chunks[i]['data'], str(chunk_error)
                    )
            
            # Generate final synthesis if we have successful chunks
            try:
                if successful_chunks > 0:
                    final_analysis = self._synthesize_chunk_results(target, chunk_results, analysis_data)
                    ai_error_message = None
                else:
                    # All chunks failed, use fallback
                    final_analysis = self._generate_fallback_comprehensive_analysis(analysis_data, "all_chunks_failed")
                    ai_error_message = "⚠️ Tüm AI chunk'ları başarısız oldu. Kural tabanlı analiz uygulanıyor..."
                    
            except Exception as synthesis_error:
                logger.warning(f"Final synthesis failed: {str(synthesis_error)}")
                final_analysis = self._generate_fallback_comprehensive_analysis(analysis_data, str(synthesis_error))
                
                error_str = str(synthesis_error).lower()
                if 'quota' in error_str or '429' in error_str:
                    ai_error_message = "⚠️ AI sentez aşamasında quota aşıldı. Parçalı analiz sonuçları kullanılıyor..."
                else:
                    ai_error_message = "⚠️ AI sentez başarısız. Parçalı analiz sonuçları kullanılıyor..."
            
            result = {
                'chunk_analyses': chunk_results,
                'final_comprehensive_analysis': final_analysis,
                'analysis_method': 'chunked_ai_analysis',
                'successful_chunks': successful_chunks,
                'total_chunks': len(prompts),
                'threat_level': threat_level,
                'ai_error_message': ai_error_message,
                'rate_limit_status': self.rate_limit_manager.get_status()
            }
            
            # Cache the result
            self.cache_manager.save_analysis_to_cache(target, analysis_data, result)
            return result
            
        except Exception as e:
            logger.warning(f"Chunked AI analysis error: {str(e)}")
            fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
            
            error_str = str(e).lower()
            if 'quota' in error_str or '429' in error_str:
                fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: OpenAI API kotası aşıldı. Kural tabanlı analiz uygulanıyor..."
            else:
                fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: Teknik bir hata oluştu. Kural tabanlı analiz uygulanıyor..."
                
            self.cache_manager.save_analysis_to_cache(target, analysis_data, fallback_result)
            return fallback_result

    def _should_process_chunk(self, chunk: Dict[str, Any], threat_level: str) -> bool:
        """Chunk'ın işlenip işlenmeyeceğini belirle"""
        # Yüksek risk durumunda tüm chunk'ları işle
        if threat_level == 'HIGH':
            return True
        
        # Orta risk durumunda ana chunk'ları işle
        if threat_level == 'MEDIUM':
            return chunk.get('chunk_type') != 'categories'
        
        # Düşük risk durumunda sadece temel chunk'ları işle
        return chunk.get('chunk_type') in ['single_source', 'basic_info']

    def _synthesize_chunk_results(self, target: str, chunk_results: Dict[str, str], analysis_data: Dict[str, Any]) -> str:
        """Chunk sonuçlarını birleştirip final analiz oluştur"""
        # Chunk sonuçlarını birleştir
        combined_analysis = "\n\n".join([
            f"### {source.replace('_data', '').title()}:\n{result}"
            for source, result in chunk_results.items()
        ])
        
        # Get summary stats
        summary_stats = self._get_analysis_summary_stats(analysis_data)
        
        synthesis_prompt = f"""Hedef: {target}

Aşağıdaki parçalı güvenlik analizlerini değerlendirdim:

{combined_analysis}

## Özet İstatistikler:
{json.dumps(summary_stats, indent=2, ensure_ascii=False)}

Bu analizleri birleştirerek kapsamlı bir güvenlik değerlendirmesi yap:

1. **GENEL RİSK SEVİYESİ** (Kritik/Yüksek/Orta/Düşük)

2. **ANA BULGULAR** (3-4 önemli nokta)

3. **ÖNERİLER** (Pratik öneriler)

4. **SONUÇ** (Net sonuç ve eylem önerisi)

Profesyonel ve özet bir analiz sun (maksimum 300 kelime):"""
        
        response = self._make_openai_request([
            {
                "role": "system",
                "content": "Sen kıdemli bir siber güvenlik uzmanısın. Parçalı analizleri birleştirerek kapsamlı değerlendirmeler yapıyorsun."
            },
            {
                "role": "user",
                "content": synthesis_prompt
            }
        ], max_tokens=600, temperature=0.2)  # Free tier için optimize edilmiş synthesis
        
        return response.choices[0].message.content.strip()

    def _assess_threat_level(self, analysis_data: Dict[str, Any]) -> str:
        """Threat seviyesini belirle API çağrılarını optimize etmek için"""
        score = 0
        
        # VirusTotal skorları
        vt = analysis_data.get('virustotal_data', {})
        if vt and 'error' not in vt:
            score += vt.get('malicious_count', 0) * 3
            score += vt.get('suspicious_count', 0) * 1
        
        # URLScan skorları
        urlscan = analysis_data.get('urlscan_data', {})
        if urlscan and 'error' not in urlscan:
            score += urlscan.get('malicious_domains', 0) * 2
            score += urlscan.get('suspicious_domains', 0) * 1
        
        # AbuseIPDB skorları
        abuse = analysis_data.get('abuseipdb_data', {})
        if abuse and 'error' not in abuse:
            confidence = abuse.get('abuse_confidence', 0)
            if confidence > 75:
                score += 3
            elif confidence > 50:
                score += 2
            elif confidence > 25:
                score += 1
        
        # Skorlara göre threat level belirle
        if score >= 8:
            return 'HIGH'
        elif score >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _generate_step_fallback_analysis(self, step_name: str, step_data: Dict[str, Any], error: str) -> str:
        """Tek bir step için fallback analiz oluştur"""
        if error == "low_priority_skipped":
            return f"{step_name} analizi: Düşük priorite nedeniyle atlandı (API kotası korunması)"
        
        # Basit kural tabanlı analiz
        if 'virustotal' in step_name.lower():
            malicious = step_data.get('malicious_count', 0)
            if malicious > 0:
                return f"VirusTotal: {malicious} güvenlik motoru zararlı olarak işaretlemiş (Yüksek Risk)"
            else:
                return "VirusTotal: Zararlı içerik tespit edilmedi (Temiz)"
        
        elif 'urlscan' in step_name.lower():
            malicious_domains = step_data.get('malicious_domains', 0)
            if malicious_domains > 0:
                return f"URLScan: {malicious_domains} zararlı domain tespit edildi (Risk var)"
            else:
                return "URLScan: Zararlı domain tespit edilmedi (Temiz)"
        
        elif 'abuseipdb' in step_name.lower():
            confidence = step_data.get('abuse_confidence', 0)
            if confidence > 50:
                return f"AbuseIPDB: %{confidence} kötüye kullanım güveni (Dikkatli olunmalı)"
            else:
                return "AbuseIPDB: Düşük kötüye kullanım riski (Temiz)"
        
        return f"{step_name}: Analiz tamamlanamadı ({error})"

    def _generate_fallback_comprehensive_analysis(self, analysis_data: Dict[str, Any], error: str) -> str:
        """Generate rule-based comprehensive analysis when AI fails"""
        try:
            # Risk seviyesini belirle
            risk_factors = []
            total_threats = 0
            
            # URLScan verileri analizi
            urlscan = analysis_data.get('urlscan_data', {})
            if urlscan and 'error' not in urlscan:
                malicious_domains = urlscan.get('malicious_domains', 0)
                suspicious_domains = urlscan.get('suspicious_domains', 0)
                if malicious_domains > 0:
                    risk_factors.append(f"URLScan: {malicious_domains} zararlı domain")
                    total_threats += malicious_domains
                if suspicious_domains > 0:
                    risk_factors.append(f"URLScan: {suspicious_domains} şüpheli domain")
            
            # VirusTotal verileri analizi
            vt = analysis_data.get('virustotal_data', {})
            if vt and 'error' not in vt:
                malicious = vt.get('malicious_count', 0)
                suspicious = vt.get('suspicious_count', 0)
                if malicious > 0:
                    risk_factors.append(f"VirusTotal: {malicious} motor zararlı tespit")
                    total_threats += malicious
                if suspicious > 0:
                    risk_factors.append(f"VirusTotal: {suspicious} motor şüpheli tespit")
            
            # AbuseIPDB verileri analizi
            abuse = analysis_data.get('abuseipdb_data', {})
            if abuse and 'error' not in abuse:
                confidence = abuse.get('abuse_confidence', 0)
                reports = abuse.get('total_reports', 0)
                if confidence > 50:
                    risk_factors.append(f"AbuseIPDB: %{confidence} kötüye kullanım güveni")
                    total_threats += 1
                if reports > 0:
                    risk_factors.append(f"AbuseIPDB: {reports} kötüye kullanım raporu")
            
            # Risk seviyesi belirleme
            if total_threats >= 5:
                risk_level = "KRİTİK"
            elif total_threats >= 3:
                risk_level = "YÜKSEK"
            elif total_threats >= 1:
                risk_level = "ORTA"
            elif len(risk_factors) > 0:
                risk_level = "DÜŞÜK"
            else:
                risk_level = "DÜŞÜK"
            
            # Hata mesajına göre özel durumlar
            error_note = ""
            if 'quota' in error.lower() or '429' in error:
                error_note = "\n💡 Not: AI analizi OpenAI API kotası nedeniyle kullanılamıyor."
            elif 'timeout' in error.lower():
                error_note = "\n💡 Not: AI analizi bağlantı zaman aşımı nedeniyle kullanılamıyor."
            else:
                error_note = "\n💡 Not: AI analizi teknik hata nedeniyle kullanılamıyor."
            
            return f"""## GENEL RİSK SEVİYESİ: {risk_level}

### ANA BULGULAR:
{"- " + chr(10).join(risk_factors) if risk_factors else "- Tüm güvenlik kaynakları temiz sonuç verdi"}
{"- Bilinen tehdit tespit edilmedi" if total_threats == 0 else f"- Toplam {total_threats} güvenlik tehdidi tespit edildi"}
- Genel güvenlik durumu {"iyi" if total_threats == 0 else "dikkat gerektiriyor"}

### ÖNERİLER:
{"- Normal güvenlik önlemleri yeterli" if total_threats == 0 else "- Ek güvenlik önlemleri alınmalı"}
- Güncel güvenlik yazılımı kullanmaya devam edin
- Düzenli güvenlik taraması yapın
{"- Şüpheli aktiviteler için sistemi izleyin" if total_threats > 0 else ""}

### SONUÇ:
{risk_level.lower().capitalize()} risk seviyesi. {"Hedef güvenli görünüyor ancak sürekli dikkatli olun." if total_threats == 0 else "Dikkatli olun ve ek güvenlik önlemleri değerlendirin."}
{error_note}

Not: Bu analiz AI desteği olmadan temel kurallara dayalı olarak oluşturulmuştur."""
            
        except Exception as fallback_error:
            logger.error(f"Fallback comprehensive analysis error: {str(fallback_error)}")
            return f"""## GENEL RİSK SEVİYESİ: DÜŞÜK

### ANA BULGULAR:
- Temel güvenlik analizi tamamlandı
- AI analizi kullanılamadı

### ÖNERİLER:
- Manuel güvenlik incelemesi yapın
- Güncel güvenlik yazılımı kullanın

### SONUÇ:
Manuel inceleme önerilir. AI analizi şu anda kullanılamıyor.

Not: Bu temel analiz kurallara dayalı olarak oluşturulmuştur."""

    def _format_single_source_data(self, source: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format data for single source analysis"""
        if source == 'urlscan_data':
            return {
                'Tarama Durumu': data.get('page_status'),
                'Zararlı Domain Sayısı': data.get('malicious_domains', 0),
                'Şüpheli Domain Sayısı': data.get('suspicious_domains', 0),
                'Genel Değerlendirme': data.get('overall_verdict', {}),
                'Ülke': data.get('country'),
                'IP': data.get('ip'),
                'Motor Değerlendirmeleri': data.get('engines_verdict', {})
            }
        elif source == 'virustotal_data':
            return {
                'Hedef Tipi': data.get('target_type'),
                'Zararlı Tespit': data.get('malicious_count', 0),
                'Şüpheli Tespit': data.get('suspicious_count', 0),
                'Temiz Tespit': data.get('clean_count', 0),
                'Toplam Motor': data.get('total_engines', 0),
                'Reputation Skoru': data.get('reputation', 0),
                'Ülke': data.get('country'),
                'Kategoriler': data.get('categories', {})
            }
        elif source == 'abuseipdb_data':
            return {
                'IP Adresi': data.get('ip_address'),
                'Kötüye Kullanım Güveni': f"%{data.get('abuse_confidence', 0)}",
                'Toplam Rapor': data.get('total_reports', 0),
                'Risk Seviyesi': data.get('risk_level'),
                'Ülke': data.get('country_name'),
                'ISP': data.get('isp'),
                'Beyaz Liste': data.get('is_whitelisted'),
                'Son Rapor': data.get('last_reported_at')
            }
        return data

    def _get_analysis_summary_stats(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get summary statistics from all analyses"""
        stats = {
            'toplam_kaynak': 0,
            'basarili_kaynak': 0,
            'toplam_tehdit_tespiti': 0,
            'en_yüksek_risk_skoru': 0
        }
        
        sources = ['urlscan_data', 'virustotal_data', 'abuseipdb_data']
        
        for source in sources:
            stats['toplam_kaynak'] += 1
            data = analysis_data.get(source, {})
            
            if data and 'error' not in data:
                stats['basarili_kaynak'] += 1
                
                # Count threats
                if source == 'urlscan_data':
                    threats = data.get('malicious_domains', 0) + data.get('suspicious_domains', 0)
                    stats['toplam_tehdit_tespiti'] += threats
                elif source == 'virustotal_data':
                    threats = data.get('malicious_count', 0) + data.get('suspicious_count', 0)
                    stats['toplam_tehdit_tespiti'] += threats
                    # Update max risk score
                    if data.get('total_engines', 0) > 0:
                        risk_ratio = (data.get('malicious_count', 0) / data.get('total_engines', 1)) * 100
                        stats['en_yüksek_risk_skoru'] = max(stats['en_yüksek_risk_skoru'], risk_ratio)
                elif source == 'abuseipdb_data':
                    confidence = data.get('abuse_confidence', 0)
                    if confidence > 25:
                        stats['toplam_tehdit_tespiti'] += 1
                    stats['en_yüksek_risk_skoru'] = max(stats['en_yüksek_risk_skoru'], confidence)
        
        return stats

    def _generate_comprehensive_fallback_analysis(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive fallback analysis using enhanced rule-based analyzer"""
        try:
            # Use the enhanced rule-based analyzer for comprehensive analysis
            analysis_result = self.enhanced_rule_analyzer.analyze_comprehensive(target, analysis_data)
            
            # Format the response in the expected structure
            return {
                'analysis': analysis_result.get('final_comprehensive_analysis', 'Gelişmiş kural tabanlı analiz tamamlandı.'),
                'risk_score': analysis_result.get('risk_level', 'Medium'),
                'recommendations': [],  # Enhanced analyzer doesn't return recommendations in this format
                'summary': {
                    'total_sources': len([k for k in analysis_data.keys() if '_data' in k and 'error' not in analysis_data.get(k, {})]),
                    'threat_level': analysis_result.get('risk_level', 'Medium'),
                    'confidence': analysis_result.get('confidence', 'Medium'),
                    'threat_count': analysis_result.get('threat_count', 0),
                    'numeric_score': analysis_result.get('risk_score', 50)
                },
                'individual_analyses': analysis_result.get('step_analyses', {}),
                'method': 'enhanced_rule_based',
                'fallback_reason': 'AI unavailable - using enhanced rule-based analysis'
            }
        except Exception as e:
            logger.error(f"Enhanced rule analyzer failed: {e}")
            # Fallback to basic rule analysis
            return self._generate_basic_fallback_analysis(target, analysis_data)
    
    def _generate_basic_fallback_analysis(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate basic fallback analysis when enhanced analyzer fails"""
        step_analyses = {}
        
        # Individual source analyses
        urlscan_data = analysis_data.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            malicious = urlscan_data.get('malicious_domains', 0)
            suspicious = urlscan_data.get('suspicious_domains', 0)
            if malicious > 0 or suspicious > 0:
                step_analyses['urlscan_data'] = f"URLScan.io: {malicious} zararlı ve {suspicious} şüpheli domain tespit edildi. Bu, hedefin riskli olabileceğini gösteriyor."
            else:
                step_analyses['urlscan_data'] = "URLScan.io: Zararlı veya şüpheli içerik tespit edilmedi. Hedef bu açıdan güvenli görünüyor."
        else:
            step_analyses['urlscan_data'] = "URLScan.io verisi mevcut değil."
        
        virustotal_data = analysis_data.get('virustotal_data', {})
        if virustotal_data and 'error' not in virustotal_data:
            malicious = virustotal_data.get('malicious_count', 0)
            total = virustotal_data.get('total_engines', 0)
            if malicious > 0:
                step_analyses['virustotal_data'] = f"VirusTotal: {malicious}/{total} güvenlik motoru zararlı olarak işaretledi. Risk seviyesi yüksek."
            else:
                step_analyses['virustotal_data'] = f"VirusTotal: {total} güvenlik motorunun hiçbiri zararlı olarak işaretlemedi. Temiz görünüyor."
        else:
            step_analyses['virustotal_data'] = "VirusTotal verisi mevcut değil."
        
        abuseipdb_data = analysis_data.get('abuseipdb_data', {})
        if abuseipdb_data and 'error' not in abuseipdb_data:
            confidence = abuseipdb_data.get('abuse_confidence', 0)
            reports = abuseipdb_data.get('total_reports', 0)
            if confidence > 50:
                step_analyses['abuseipdb_data'] = f"AbuseIPDB: %{confidence} kötüye kullanım güveni ile yüksek risk. {reports} kötüye kullanım raporu mevcut."
            elif confidence > 0:
                step_analyses['abuseipdb_data'] = f"AbuseIPDB: %{confidence} kötüye kullanım güveni ile düşük-orta risk. {reports} rapor mevcut."
            else:
                step_analyses['abuseipdb_data'] = "AbuseIPDB: Kötüye kullanım raporu bulunmuyor. Temiz IP adresi."
        else:
            step_analyses['abuseipdb_data'] = "AbuseIPDB verisi mevcut değil."
        
        # Generate final analysis
        threat_count = 0
        if urlscan_data and (urlscan_data.get('malicious_domains', 0) > 0 or urlscan_data.get('suspicious_domains', 0) > 0):
            threat_count += 1
        if virustotal_data and virustotal_data.get('malicious_count', 0) > 0:
            threat_count += 1
        if abuseipdb_data and abuseipdb_data.get('abuse_confidence', 0) > 25:
            threat_count += 1
        
        if threat_count >= 2:
            risk_level = "YÜKSEK"
            final_analysis = f"""
## GENEL RİSK SEVİYESİ: {risk_level}

### ANA BULGULAR:
- Birden fazla güvenlik kaynağı tehdit tespit etti
- Bu hedef potansiyel olarak zararlı olabilir
- Dikkatli yaklaşım gereklidir

### ÖNERİLER:
- Bu hedefe erişimden kaçının
- Güvenlik yazılımınızı güncel tutun
- Şüpheli aktivite için izleme yapın

### SONUÇ:
Yüksek risk tespit edildi. Bu hedefle etkileşime girmeden önce ek güvenlik önlemleri alın.

Not: Bu analiz AI desteği olmadan temel kurallara dayalı olarak oluşturulmuştur.
"""
        elif threat_count == 1:
            risk_level = "ORTA"
            final_analysis = f"""
## GENEL RİSK SEVİYESİ: {risk_level}

### ANA BULGULAR:
- Bir güvenlik kaynağı potansiyel risk tespit etti
- Diğer kaynaklar temiz gösteriyor
- Orta düzeyde dikkat gerekli

### ÖNERİLER:
- Dikkatli şekilde erişim sağlayın
- Güvenlik yazılımınızı aktif tutun
- Şüpheli davranış gözlemleyin

### SONUÇ:
Orta seviye risk. Standart güvenlik önlemleri ile dikkatli erişim sağlanabilir.

Not: Bu analiz AI desteği olmadan temel kurallara dayalı olarak oluşturulmuştur.
"""
        else:
            risk_level = "DÜŞÜK"
            final_analysis = f"""
## GENEL RİSK SEVİYESİ: {risk_level}

### ANA BULGULAR:
- Tüm güvenlik kaynakları temiz sonuç verdi
- Bilinen tehdit tespit edilmedi
- Genel güvenlik durumu iyi

### ÖNERİLER:
- Normal güvenlik önlemleri yeterli
- Güncel güvenlik yazılımı kullanmaya devam edin
- Düzenli güvenlik taraması yapın

### SONUÇ:
Düşük risk seviyesi. Hedef güvenli görünüyor ancak sürekli dikkatli olun.

Not: Bu analiz AI desteği olmadan temel kurallara dayalı olarak oluşturulmuştur.
"""
        
        return {
            'step_by_step_analysis': step_analyses,
            'final_comprehensive_analysis': final_analysis,
            'analysis_method': 'fallback_rule_based',
            'ai_error_message': "⚠️ AI analiz yapılamadı: Kural tabanlı analiz uygulandı"
        }
    
    def _format_data_for_ai(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format analysis data for AI consumption"""
        formatted_data = {}
        
        # URLScan data
        urlscan_data = analysis_data.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            formatted_data['URLScan'] = {
                'Zararlı domain sayısı': urlscan_data.get('malicious_domains', 0),
                'Şüpheli domain sayısı': urlscan_data.get('suspicious_domains', 0),
                'Genel değerlendirme': urlscan_data.get('overall_verdict', {}),
                'Ülke': urlscan_data.get('country'),
                'IP adresi': urlscan_data.get('ip'),
                'Durum': urlscan_data.get('page_status')
            }
        
        # VirusTotal data
        virustotal_data = analysis_data.get('virustotal_data', {})
        if virustotal_data and 'error' not in virustotal_data:
            formatted_data['VirusTotal'] = {
                'Zararlı tespit eden motor sayısı': virustotal_data.get('malicious_count', 0),
                'Şüpheli tespit eden motor sayısı': virustotal_data.get('suspicious_count', 0),
                'Temiz tespit eden motor sayısı': virustotal_data.get('clean_count', 0),
                'Toplam motor sayısı': virustotal_data.get('total_engines', 0),
                'Reputation skoru': virustotal_data.get('reputation', 0),
                'Kategoriler': virustotal_data.get('categories', {}),
                'Hedef tipi': virustotal_data.get('target_type')
            }
        
        # AbuseIPDB data
        abuseipdb_data = analysis_data.get('abuseipdb_data', {})
        if abuseipdb_data and 'error' not in abuseipdb_data:
            formatted_data['AbuseIPDB'] = {
                'IP adresi': abuseipdb_data.get('ip_address'),
                'Kötüye kullanım güven yüzdesi': abuseipdb_data.get('abuse_confidence', 0),
                'Toplam rapor sayısı': abuseipdb_data.get('total_reports', 0),
                'Risk seviyesi': abuseipdb_data.get('risk_level'),
                'Ülke': abuseipdb_data.get('country_name'),
                'ISP': abuseipdb_data.get('isp'),
                'Beyaz listede mi': abuseipdb_data.get('is_whitelisted')
            }
        
        return formatted_data
    
    def _create_analysis_prompt(self, target: str, formatted_data: Dict[str, Any]) -> str:
        """Create analysis prompt for AI"""
        prompt = f"""
Hedef: {target}

Elimde aşağıdaki güvenlik verilerini var:

{json.dumps(formatted_data, indent=2, ensure_ascii=False)}

Bu verileri bir siber güvenlik uzmanı gibi analiz et ve aşağıdaki konuları kapsayan detaylı bir değerlendirme yap:

1. GENEL RİSK SEVİYESİ: Bu hedefin genel risk seviyesi nedir? (Düşük/Orta/Yüksek/Kritik)

2. TESPİT EDİLEN TEHDITLER: Hangi potansiyel tehditler tespit edildi?

3. VERİ ANALİZİ: Her bir kaynaktan gelen veriler ne anlama geliyor?

4. ÖNERİLER: Bu hedefe karşı hangi güvenlik önlemleri alınmalı?

5. SONUÇ: Kısa ve net bir sonuç özeti.

Lütfen analizi mesleki, anlaşılır ve Türkçe olarak yap. Teknik terimler kullanırken açıklama da ekle.
        """
        return prompt
    
    def _generate_fallback_analysis(self, target: str, analysis_data: Dict[str, Any]) -> str:
        """Generate basic analysis when AI is not available"""
        analysis_parts = []
        analysis_parts.append(f"Hedef: {target}")
        analysis_parts.append("\n=== GÜVENLIK ANALİZİ ===")
        
        # Analyze URLScan data
        urlscan_data = analysis_data.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            malicious = urlscan_data.get('malicious_domains', 0)
            suspicious = urlscan_data.get('suspicious_domains', 0)
            if malicious > 0 or suspicious > 0:
                analysis_parts.append(f"\n⚠️ URLScan.io: {malicious} zararlı, {suspicious} şüpheli domain tespit edildi.")
            else:
                analysis_parts.append(f"\n✅ URLScan.io: Zararlı veya şüpheli içerik tespit edilmedi.")
        
        # Analyze VirusTotal data
        virustotal_data = analysis_data.get('virustotal_data', {})
        if virustotal_data and 'error' not in virustotal_data:
            malicious = virustotal_data.get('malicious_count', 0)
            total = virustotal_data.get('total_engines', 0)
            if malicious > 0:
                analysis_parts.append(f"\n⚠️ VirusTotal: {malicious}/{total} güvenlik motoru zararlı olarak işaretledi.")
            else:
                analysis_parts.append(f"\n✅ VirusTotal: Hiçbir güvenlik motoru zararlı olarak işaretlemedi.")
        
        # Analyze AbuseIPDB data
        abuseipdb_data = analysis_data.get('abuseipdb_data', {})
        if abuseipdb_data and 'error' not in abuseipdb_data:
            confidence = abuseipdb_data.get('abuse_confidence', 0)
            reports = abuseipdb_data.get('total_reports', 0)
            if confidence > 0:
                analysis_parts.append(f"\n⚠️ AbuseIPDB: %{confidence} kötüye kullanım güveni, {reports} rapor var.")
            else:
                analysis_parts.append(f"\n✅ AbuseIPDB: Kötüye kullanım raporu bulunmuyor.")
        
        # Generate recommendation
        analysis_parts.append("\n=== ÖNERİLER ===")
        
        # Check if any threats detected
        threats_detected = False
        if urlscan_data and (urlscan_data.get('malicious_domains', 0) > 0 or urlscan_data.get('suspicious_domains', 0) > 0):
            threats_detected = True
        if virustotal_data and virustotal_data.get('malicious_count', 0) > 0:
            threats_detected = True
        if abuseipdb_data and abuseipdb_data.get('abuse_confidence', 0) > 25:
            threats_detected = True
        
        if threats_detected:
            analysis_parts.append("🚨 Bu hedef riskli görünüyor. Erişimden kaçının ve güvenlik önlemlerinizi artırın.")
        else:
            analysis_parts.append("✅ Mevcut veriler hedefin güvenli olduğunu gösteriyor, ancak sürekli dikkatli olun.")
        
        analysis_parts.append("\nNot: Bu analiz AI desteği olmadan temel kurallara dayalı olarak oluşturulmuştur.")
        
        return "\n".join(analysis_parts)
    
    def _generate_demo_analysis(self, source_name: str, data: dict) -> str:
        """Generate demo analysis when AI is not available"""
        if 'urlscan' in source_name.lower():
            malicious = data.get('malicious_domains', 0)
            suspicious = data.get('suspicious_domains', 0)
            if malicious > 0:
                return f"URLScan.io taramasında {malicious} zararlı domain tespit edildi. Bu site güvenli değil."
            elif suspicious > 0:
                return f"URLScan.io taramasında {suspicious} şüpheli domain tespit edildi. Dikkatli olunmalı."
            else:
                return "URLScan.io taramasında herhangi bir güvenlik tehdidi tespit edilmedi. Site temiz görünüyor."
        
        elif 'virustotal' in source_name.lower():
            malicious = data.get('malicious_count', 0)
            suspicious = data.get('suspicious_count', 0)
            clean = data.get('clean_count', 0)
            if malicious > 0:
                return f"VirusTotal'da {malicious} antivirus motoru zararlı yazılım tespit etti. Risk yüksek."
            elif suspicious > 0:
                return f"VirusTotal'da {suspicious} antivirus motoru şüpheli aktivite bildirdi. Orta risk."
            else:
                return f"VirusTotal'da {clean} antivirus motoru temiz rapor verdi. Güvenli görünüyor."
        
        elif 'abuseipdb' in source_name.lower():
            confidence = data.get('abuse_confidence', 0)
            reports = data.get('total_reports', 0)
            if confidence > 75:
                return f"AbuseIPDB'de %{confidence} güvenle kötüye kullanım tespit edildi. Bu IP tehlikeli."
            elif confidence > 25:
                return f"AbuseIPDB'de %{confidence} güvenle şüpheli aktivite rapor edildi. Dikkat edilmeli."
            else:
                return "AbuseIPDB'de herhangi bir kötüye kullanım raporu bulunmadı. IP temiz görünüyor."
        
        return f"{source_name} verisi analiz edildi. Manuel inceleme önerilir."
    
    def _generate_step_fallback_analysis(self, source_name: str, data: dict, error: str) -> str:
        """Generate fallback analysis for step-by-step analysis when AI API fails"""
        # Check if it's a clean source
        if error == "clean_source":
            if 'urlscan' in source_name.lower():
                return "URLScan.io: Zararlı veya şüpheli içerik tespit edilmedi. Hedef bu açıdan güvenli görünüyor."
            elif 'virustotal' in source_name.lower():
                clean = data.get('clean_count', 0)
                total = data.get('total_engines', 0)
                return f"VirusTotal: {total} güvenlik motorunun hiçbiri zararlı olarak işaretlemedi. Temiz görünüyor."
            elif 'abuseipdb' in source_name.lower():
                return "AbuseIPDB: Kötüye kullanım raporu bulunmuyor. Temiz IP adresi."
        
        # Provide source-specific fallback analysis for threats
        if 'urlscan' in source_name.lower():
            malicious = data.get('malicious_domains', 0)
            suspicious = data.get('suspicious_domains', 0) 
            if malicious > 0 or suspicious > 0:
                return f"URLScan.io: {malicious} zararlı, {suspicious} şüpheli domain tespit edildi. Manuel inceleme gerekli."
            else:
                return "URLScan.io: Zararlı veya şüpheli içerik tespit edilmedi. Hedef bu açıdan güvenli görünüyor."
                
        elif 'virustotal' in source_name.lower():
            malicious = data.get('malicious_count', 0)
            total = data.get('total_engines', 0)
            if malicious > 0:
                return f"VirusTotal: {malicious}/{total} güvenlik motoru zararlı olarak işaretledi. Dikkat gerekli."
            else:
                return f"VirusTotal: {total} güvenlik motorunun hiçbiri zararlı olarak işaretlemedi. Temiz görünüyor."
                
        elif 'abuseipdb' in source_name.lower():
            confidence = data.get('abuse_confidence', 0)
            reports = data.get('total_reports', 0)
            if confidence > 50 or reports > 0:
                return f"AbuseIPDB: %{confidence} güven skoruyla {reports} kötüye kullanım raporu var. Risk mevcut."
            else:
                return "AbuseIPDB: Kötüye kullanım raporu bulunmuyor. Temiz IP adresi."
                
        return f"{source_name}: Manuel inceleme gerekli (AI analizi kullanılamıyor)."
    
    def _generate_error_fallback_analysis(self, data: dict, error: str) -> str:
        """Generate fallback analysis when AI API fails"""
        if 'quota' in error.lower() or '429' in error:
            return "AI analizi geçici olarak kullanılamıyor (API quota sınırı). Manuel değerlendirme: Tüm kaynaklardan alınan verilere göre manuel risk analizi yapılabilir."
        else:
            return f"AI analizi sırasında teknik hata oluştu. Ham veriler üzerinden manuel inceleme yapılabilir."
    
    def _generate_fallback_comprehensive_analysis(self, analysis_data: dict, error: str) -> str:
        """Generate comprehensive fallback analysis when AI API fails"""
        analysis_parts = []
        
        if 'quota' in error.lower() or '429' in error:
            analysis_parts.append("🤖 AI Analizi Geçici Olarak Kullanılamıyor")
            analysis_parts.append("\nOpenAI API quota sınırına ulaşıldı. Aşağıda temel güvenlik değerlendirmesi sunulmaktadır:")
        else:
            analysis_parts.append("🤖 AI Analizi Hatası")
            analysis_parts.append(f"\nTeknik hata nedeniyle AI analizi yapılamadı. Temel değerlendirme:")
        
        analysis_parts.append("\n" + "="*50)
        analysis_parts.append("📊 TEMEL GÜVENLİK DEĞERLENDİRMESİ")
        analysis_parts.append("="*50)
        
        # Analyze URLScan data
        urlscan_data = analysis_data.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            malicious = urlscan_data.get('malicious_domains', 0)
            suspicious = urlscan_data.get('suspicious_domains', 0)
            analysis_parts.append(f"\n🔍 URLScan.io Sonuçları:")
            if malicious > 0:
                analysis_parts.append(f"   ⚠️ {malicious} zararlı domain tespit edildi - YÜKSEKRİSK")
            elif suspicious > 0:
                analysis_parts.append(f"   ⚠️ {suspicious} şüpheli domain tespit edildi - ORTA RİSK")
            else:
                analysis_parts.append("   ✅ Zararlı veya şüpheli domain tespit edilmedi")
        
        # Analyze VirusTotal data
        virustotal_data = analysis_data.get('virustotal_data', {})
        if virustotal_data and 'error' not in virustotal_data:
            malicious = virustotal_data.get('malicious_count', 0)
            suspicious = virustotal_data.get('suspicious_count', 0)
            total = virustotal_data.get('total_engines', 0)
            analysis_parts.append(f"\n🛡️ VirusTotal Sonuçları:")
            if malicious > 0:
                analysis_parts.append(f"   ⚠️ {malicious}/{total} güvenlik motoru zararlı tespit etti - YÜKSEK RİSK")
            elif suspicious > 0:
                analysis_parts.append(f"   ⚠️ {suspicious}/{total} güvenlik motoru şüpheli tespit etti - ORTA RİSK")
            else:
                analysis_parts.append(f"   ✅ {total} güvenlik motorunun hiçbiri zararlı tespit etmedi")
        
        # Analyze AbuseIPDB data
        abuseipdb_data = analysis_data.get('abuseipdb_data', {})
        if abuseipdb_data and 'error' not in abuseipdb_data:
            confidence = abuseipdb_data.get('abuse_confidence', 0)
            reports = abuseipdb_data.get('total_reports', 0)
            analysis_parts.append(f"\n🚨 AbuseIPDB Sonuçları:")
            if confidence > 75:
                analysis_parts.append(f"   ⚠️ %{confidence} güvenle kötüye kullanım tespit edildi - YÜKSEK RİSK")
            elif confidence > 25:
                analysis_parts.append(f"   ⚠️ %{confidence} güvenle şüpheli aktivite - ORTA RİSK")
            else:
                analysis_parts.append("   ✅ Kötüye kullanım raporu bulunmuyor")
        
        # Overall assessment
        analysis_parts.append("\n" + "="*50)
        analysis_parts.append("🎯 GENEL DEĞERLENDİRME")
        analysis_parts.append("="*50)
        
        # Determine overall risk
        high_risk_indicators = 0
        medium_risk_indicators = 0
        
        if urlscan_data:
            if urlscan_data.get('malicious_domains', 0) > 0:
                high_risk_indicators += 1
            elif urlscan_data.get('suspicious_domains', 0) > 0:
                medium_risk_indicators += 1
        
        if virustotal_data:
            if virustotal_data.get('malicious_count', 0) > 0:
                high_risk_indicators += 1
            elif virustotal_data.get('suspicious_count', 0) > 0:
                medium_risk_indicators += 1
        
        if abuseipdb_data:
            confidence = abuseipdb_data.get('abuse_confidence', 0)
            if confidence > 75:
                high_risk_indicators += 1
            elif confidence > 25:
                medium_risk_indicators += 1
        
        if high_risk_indicators > 0:
            analysis_parts.append("\n🚨 YÜKSEK RİSK TESPIT EDİLDİ!")
            analysis_parts.append("   • Bu hedefle etkileşime geçmekten kaçının")
            analysis_parts.append("   • Güvenlik duvarı kurallarınızı gözden geçirin")
            analysis_parts.append("   • Sistem yöneticinizi bilgilendirin")
        elif medium_risk_indicators > 0:
            analysis_parts.append("\n⚠️ ORTA DÜZEYRİSK TESPIT EDİLDİ")
            analysis_parts.append("   • Dikkatli olun ve ek güvenlik önlemleri alın")
            analysis_parts.append("   • Bu hedefle etkileşimi sınırlayın")
            analysis_parts.append("   • Sürekli izleme yapın")
        else:
            analysis_parts.append("\n✅ DÜŞÜK RİSK")
            analysis_parts.append("   • Mevcut veriler güvenli olduğunu gösteriyor")
            analysis_parts.append("   • Yine de temel güvenlik kurallarına uyun")
            analysis_parts.append("   • Periyodik kontroller yapmaya devam edin")
        
        analysis_parts.append("\n" + "="*50)
        analysis_parts.append("📝 NOT: Bu analiz AI desteği olmadan temel kurallar")
        analysis_parts.append("çerçevesinde yapılmıştır. Daha detaylı analiz için")
        analysis_parts.append("OpenAI API quota'nızı yenilemeniz önerilir.")
        analysis_parts.append("="*50)
        
        return "\n".join(analysis_parts)
