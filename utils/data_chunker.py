import logging
from typing import Dict, Any, List, Tuple
import json

logger = logging.getLogger(__name__)

class DataChunker:
    """Analiz verilerini küçük parçalara bölen sınıf"""
    
    def __init__(self):
        self.max_tokens_per_chunk = 1500  # Free tier için optimize edilmiş chunk boyutu
        
    def estimate_tokens(self, text: str) -> int:
        """Token sayısını tahmin et"""
        return max(1, len(text) // 4)
    
    def chunk_analysis_data(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analiz verilerini küçük parçalara böl
        
        Args:
            analysis_data: Tüm güvenlik API'lerinden gelen veriler
            
        Returns:
            List[Dict]: Her biri AI'ya ayrı ayrı gönderilebilecek parçalar
        """
        chunks = []
        
        # Her bir veri kaynağını ayrı chunk olarak ayır
        sources = ['urlscan_data', 'virustotal_data', 'abuseipdb_data']
        
        for source in sources:
            if source in analysis_data and analysis_data[source] and 'error' not in analysis_data[source]:
                chunk_data = self._create_source_chunk(source, analysis_data[source])
                if chunk_data:
                    chunks.append({
                        'source': source,
                        'data': chunk_data,
                        'chunk_type': 'single_source'
                    })
        
        # Eğer veri çok büyükse, kaynak içinde de böl
        large_chunks = []
        for chunk in chunks:
            if self._is_chunk_too_large(chunk):
                sub_chunks = self._split_large_chunk(chunk)
                large_chunks.extend(sub_chunks)
            else:
                large_chunks.append(chunk)
        
        logger.info(f"Created {len(large_chunks)} data chunks for analysis")
        return large_chunks
    
    def _create_source_chunk(self, source: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Tek bir kaynak için optimize edilmiş chunk oluştur"""
        if source == 'urlscan_data':
            return {
                'source_name': 'URLScan.io',
                'malicious_domains': data.get('malicious_domains', 0),
                'suspicious_domains': data.get('suspicious_domains', 0),
                'country': data.get('country'),
                'ip': data.get('ip'),
                'page_status': data.get('page_status'),
                'verdict_summary': data.get('overall_verdict', {})
            }
        
        elif source == 'virustotal_data':
            return {
                'source_name': 'VirusTotal',
                'target_type': data.get('target_type'),
                'malicious_count': data.get('malicious_count', 0),
                'suspicious_count': data.get('suspicious_count', 0),
                'clean_count': data.get('clean_count', 0),
                'total_engines': data.get('total_engines', 0),
                'reputation': data.get('reputation', 0),
                'country': data.get('country'),
                'categories': data.get('categories', {})
            }
        
        elif source == 'abuseipdb_data':
            return {
                'source_name': 'AbuseIPDB',
                'ip_address': data.get('ip_address'),
                'abuse_confidence': data.get('abuse_confidence', 0),
                'total_reports': data.get('total_reports', 0),
                'risk_level': data.get('risk_level'),
                'country_name': data.get('country_name'),
                'isp': data.get('isp'),
                'is_whitelisted': data.get('is_whitelisted')
            }
        
        return {}
    
    def _is_chunk_too_large(self, chunk: Dict[str, Any]) -> bool:
        """Chunk'ın çok büyük olup olmadığını kontrol et"""
        chunk_text = json.dumps(chunk, ensure_ascii=False)
        estimated_tokens = self.estimate_tokens(chunk_text)
        return estimated_tokens > self.max_tokens_per_chunk
    
    def _split_large_chunk(self, chunk: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Büyük chunk'ı daha küçük parçalara böl"""
        # Bu örnekte basit bir bölme yapıyoruz
        # Gerçek uygulamada daha sofistike bölme stratejileri kullanılabilir
        
        data = chunk['data']
        source = chunk['source']
        
        sub_chunks = []
        
        # Ana bilgileri tutan temel chunk
        base_chunk = {
            'source': source,
            'data': {
                'source_name': data.get('source_name'),
                'basic_info': True
            },
            'chunk_type': 'basic_info'
        }
        
        # Kaynak tipine göre özel bölme
        if source == 'virustotal_data':
            base_chunk['data'].update({
                'malicious_count': data.get('malicious_count', 0),
                'suspicious_count': data.get('suspicious_count', 0),
                'total_engines': data.get('total_engines', 0)
            })
            
            # Kategorileri ayrı chunk'a al
            if data.get('categories'):
                category_chunk = {
                    'source': source,
                    'data': {
                        'source_name': data.get('source_name'),
                        'categories': data.get('categories')
                    },
                    'chunk_type': 'categories'
                }
                sub_chunks.append(category_chunk)
        
        elif source == 'abuseipdb_data':
            base_chunk['data'].update({
                'abuse_confidence': data.get('abuse_confidence', 0),
                'total_reports': data.get('total_reports', 0),
                'risk_level': data.get('risk_level')
            })
        
        elif source == 'urlscan_data':
            base_chunk['data'].update({
                'malicious_domains': data.get('malicious_domains', 0),
                'suspicious_domains': data.get('suspicious_domains', 0),
                'page_status': data.get('page_status')
            })
        
        sub_chunks.insert(0, base_chunk)
        return sub_chunks
    
    def create_analysis_prompts(self, chunks: List[Dict[str, Any]], target: str) -> List[Tuple[str, int]]:
        """
        Her chunk için optimize edilmiş AI prompt'ları oluştur
        
        Returns:
            List[Tuple[str, int]]: (prompt, estimated_tokens) tuples
        """
        prompts = []
        
        for i, chunk in enumerate(chunks):
            source = chunk['source']
            data = chunk['data']
            chunk_type = chunk.get('chunk_type', 'single_source')
            
            # Kaynak tipine göre özelleştirilmiş prompt
            if source == 'urlscan_data':
                prompt = self._create_urlscan_prompt(target, data, chunk_type)
            elif source == 'virustotal_data':
                prompt = self._create_virustotal_prompt(target, data, chunk_type)
            elif source == 'abuseipdb_data':
                prompt = self._create_abuseipdb_prompt(target, data, chunk_type)
            else:
                prompt = self._create_generic_prompt(target, data, source)
            
            estimated_tokens = self.estimate_tokens(prompt)
            prompts.append((prompt, estimated_tokens))
        
        return prompts
    
    def _create_urlscan_prompt(self, target: str, data: Dict[str, Any], chunk_type: str) -> str:
        """URLScan verisi için özelleştirilmiş prompt"""
        return f"""Hedef: {target}

URLScan.io güvenlik taraması sonuçlarını analiz et:

📊 Tarama Sonuçları:
- Zararlı Domain: {data.get('malicious_domains', 0)}
- Şüpheli Domain: {data.get('suspicious_domains', 0)}
- Sayfa Durumu: {data.get('page_status', 'Bilinmiyor')}
- Konum: {data.get('country', 'Bilinmiyor')}
- IP: {data.get('ip', 'Bilinmiyor')}

Bu URLScan.io verilerine dayanarak:
1. Risk seviyesi nedir?
2. Tespit edilen temel tehditler nelerdir?
3. Bu kaynağa özgü öneriler nelerdir?

Kısa ve öz bir analiz yap (maksimum 100 kelime):"""
    
    def _create_virustotal_prompt(self, target: str, data: Dict[str, Any], chunk_type: str) -> str:
        """VirusTotal verisi için özelleştirilmiş prompt"""
        if chunk_type == 'categories':
            return f"""Hedef: {target}

VirusTotal kategori analizi:

📂 Tespit Edilen Kategoriler:
{json.dumps(data.get('categories', {}), indent=2, ensure_ascii=False)}

Bu kategori bilgilerine göre:
1. Hangi kategoriler risk oluşturuyor?
2. Bu kategorilerin anlamı nedir?

Kısa kategori analizi (maksimum 80 kelime):"""
        
        return f"""Hedef: {target}

VirusTotal güvenlik taraması sonuçları:

🛡️ Tarama Sonuçları:
- Zararlı Tespit: {data.get('malicious_count', 0)}/{data.get('total_engines', 0)} motor
- Şüpheli Tespit: {data.get('suspicious_count', 0)}/{data.get('total_engines', 0)} motor
- Temiz Tespit: {data.get('clean_count', 0)}/{data.get('total_engines', 0)} motor
- Reputation Skoru: {data.get('reputation', 0)}

Bu VirusTotal verilerine dayanarak:
1. Risk seviyesi nedir?
2. Antivirus motorlarının konsensüsü nedir?
3. Bu kaynağa özgü öneriler nelerdir?

Kısa ve öz bir analiz yap (maksimum 100 kelime):"""
    
    def _create_abuseipdb_prompt(self, target: str, data: Dict[str, Any], chunk_type: str) -> str:
        """AbuseIPDB verisi için özelleştirilmiş prompt"""
        return f"""Hedef: {target}

AbuseIPDB kötüye kullanım analizi:

🚨 Kötüye Kullanım Raporu:
- Güven Skoru: %{data.get('abuse_confidence', 0)}
- Toplam Rapor: {data.get('total_reports', 0)}
- Risk Seviyesi: {data.get('risk_level', 'Bilinmiyor')}
- ISP: {data.get('isp', 'Bilinmiyor')}
- Beyaz Liste: {data.get('is_whitelisted', False)}

Bu AbuseIPDB verilerine dayanarak:
1. IP adresi ne kadar riskli?
2. Raporlanan kötüye kullanım türleri nedir?
3. Bu kaynağa özgü öneriler nelerdir?

Kısa ve öz bir analiz yap (maksimum 100 kelime):"""
    
    def _create_generic_prompt(self, target: str, data: Dict[str, Any], source: str) -> str:
        """Genel amaçlı prompt"""
        return f"""Hedef: {target}

{source} güvenlik verisi analizi:

{json.dumps(data, indent=2, ensure_ascii=False)}

Bu verilere dayanarak kısa bir güvenlik değerlendirmesi yap (maksimum 100 kelime):"""
