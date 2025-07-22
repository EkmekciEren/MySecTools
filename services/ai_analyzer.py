import os
import logging
from typing import Dict, Any, List
import json

logger = logging.getLogger(__name__)

class AIAnalyzer:
    """AI-powered security analysis using OpenAI GPT-4o"""
    
    def __init__(self):
        self.api_key = os.getenv('OPENAI_API_KEY')
        self.model = os.getenv('AI_MODEL', 'gpt-4o')
        self.max_tokens = int(os.getenv('AI_MAX_TOKENS', '2000'))
        self.temperature = float(os.getenv('AI_TEMPERATURE', '0.3'))
        
        # Initialize OpenAI client if available
        self.client = None
        if self.api_key and self.api_key != 'your_openai_api_key_here':
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            except ImportError:
                logger.error("OpenAI library not installed")
    
    def analyze_step_by_step(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate step-by-step AI analysis of security data
        
        Args:
            target: The analyzed target
            analysis_data: Combined data from all security APIs
            
        Returns:
            Dictionary with individual analyses and final summary
        """
        if not self.client:
            fallback_result = self._generate_comprehensive_fallback_analysis(target, analysis_data)
            fallback_result['ai_error_message'] = "⚠️ AI analiz yapılamadı: API anahtarı yapılandırılmamış. Kural tabanlı analiz uygulanıyor..."
            return fallback_result
        
        try:
            step_analyses = {}
            data_sources = ['urlscan_data', 'virustotal_data', 'abuseipdb_data']
            
            # Step 1: Analyze each data source individually
            for source in data_sources:
                if source in analysis_data and analysis_data[source] and 'error' not in analysis_data[source]:
                    step_analyses[source] = self._analyze_single_source(source, analysis_data[source])
                else:
                    step_analyses[source] = f"{source.replace('_data', '').title()} verisi mevcut değil veya hatalı."
            
            # Step 2: Generate comprehensive final analysis
            try:
                final_analysis = self._generate_final_comprehensive_analysis(target, analysis_data, step_analyses)
                ai_error_message = None  # Success case
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
            
            return {
                'step_by_step_analysis': step_analyses,
                'final_comprehensive_analysis': final_analysis,
                'analysis_method': 'ai_powered_step_by_step',
                'ai_error_message': ai_error_message
            }
            
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
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Sen bir siber güvenlik uzmanısın. Teknik verileri analiz edip anlaşılır değerlendirmeler yapıyorsun."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.3
            )
            
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
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "Sen kıdemli bir siber güvenlik uzmanısın. Çeşitli kaynaklardan gelen güvenlik verilerini birleştirerek kapsamlı risk değerlendirmeleri yapıyorsun. Analizin profesyonel, objektif ve pratik olmalı."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logger.warning(f"Final comprehensive analysis error: {str(e)}")
            
            # Quota hatası gibi önemli hatalar için exception'ı yeniden at
            error_str = str(e).lower()
            if 'quota' in error_str or '429' in error_str or 'authentication' in error_str or 'unauthorized' in error_str:
                raise e  # Exception'ı yukarı at ki hata mesajı ayarlanabilsin
            
            # Diğer hatalar için fallback döndür
            return self._generate_fallback_comprehensive_analysis(analysis_data, str(e))

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
        """Generate comprehensive fallback analysis when AI is not available"""
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
        # Provide source-specific fallback analysis
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
            confidence = data.get('confidence_percentage', 0)
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
