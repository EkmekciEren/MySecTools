"""
Enhanced Rule-Based Security Analysis System
Provides detailed security analysis without AI dependency
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class EnhancedRuleBasedAnalyzer:
    """Gelişmiş kural tabanlı güvenlik analiz sistemi"""
    
    def __init__(self):
        self.threat_indicators = {
            'virustotal': {
                'critical': ['malicious_count', 'suspicious_count'],
                'thresholds': {'malicious': 5, 'suspicious': 10}
            },
            'urlscan': {
                'critical': ['malicious_domains', 'suspicious_domains'],
                'thresholds': {'malicious': 3, 'suspicious': 5}
            },
            'abuseipdb': {
                'critical': ['abuse_confidence', 'total_reports'],
                'thresholds': {'confidence': 75, 'reports': 10}
            }
        }
    
    def analyze_comprehensive(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Kapsamlı kural tabanlı analiz"""
        
        # Risk assessment
        risk_assessment = self._assess_comprehensive_risk(analysis_data)
        
        # Detailed findings
        detailed_findings = self._generate_detailed_findings(analysis_data)
        
        # Security recommendations
        recommendations = self._generate_security_recommendations(risk_assessment, analysis_data)
        
        # Threat intelligence
        threat_intel = self._generate_threat_intelligence(analysis_data)
        
        # Final comprehensive analysis
        comprehensive_analysis = self._format_comprehensive_report(
            target, risk_assessment, detailed_findings, recommendations, threat_intel
        )
        
        return {
            'step_analyses': detailed_findings,
            'final_comprehensive_analysis': comprehensive_analysis,
            'analysis_method': 'enhanced_rule_based',
            'risk_level': risk_assessment['level'],
            'risk_score': risk_assessment['score'],
            'confidence': risk_assessment['confidence'],
            'threat_count': risk_assessment['threat_count'],
            'ai_error_message': "✅ Gelişmiş kural tabanlı analiz kullanıldı (AI analiz mevcut değil)"
        }
    
    def _assess_comprehensive_risk(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Kapsamlı risk değerlendirmesi"""
        score = 0
        max_score = 100
        threat_count = 0
        risk_factors = []
        
        # VirusTotal analysis
        vt_data = analysis_data.get('virustotal_data', {})
        if vt_data and 'error' not in vt_data:
            malicious = vt_data.get('malicious_count', 0)
            suspicious = vt_data.get('suspicious_count', 0)
            
            if malicious > 0:
                score += min(malicious * 15, 60)  # Max 60 points
                threat_count += malicious
                risk_factors.append(f"VirusTotal: {malicious} zararlı tespit")
                
            if suspicious > 0:
                score += min(suspicious * 5, 20)  # Max 20 points
                risk_factors.append(f"VirusTotal: {suspicious} şüpheli tespit")
        
        # URLScan analysis
        urlscan_data = analysis_data.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            mal_domains = urlscan_data.get('malicious_domains', 0)
            sus_domains = urlscan_data.get('suspicious_domains', 0)
            
            if mal_domains > 0:
                score += min(mal_domains * 10, 30)  # Max 30 points
                threat_count += mal_domains
                risk_factors.append(f"URLScan: {mal_domains} zararlı domain")
                
            if sus_domains > 0:
                score += min(sus_domains * 3, 15)  # Max 15 points
                risk_factors.append(f"URLScan: {sus_domains} şüpheli domain")
        
        # AbuseIPDB analysis
        abuse_data = analysis_data.get('abuseipdb_data', {})
        if abuse_data and 'error' not in abuse_data:
            confidence = abuse_data.get('abuse_confidence', 0)
            reports = abuse_data.get('total_reports', 0)
            
            if confidence > 0:
                score += min(confidence, 25)  # Max 25 points from confidence
                if confidence > 50:
                    threat_count += 1
                    risk_factors.append(f"AbuseIPDB: %{confidence} kötüye kullanım güveni")
                    
            if reports > 0:
                score += min(reports * 2, 15)  # Max 15 points from reports
                risk_factors.append(f"AbuseIPDB: {reports} kötüye kullanım raporu")
        
        # Risk level determination
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        elif score >= 10:
            level = "LOW"
        else:
            level = "MINIMAL"
        
        # Confidence based on data availability
        data_sources = sum([
            1 for data in [vt_data, urlscan_data, abuse_data]
            if data and 'error' not in data
        ])
        confidence = min(95, 40 + (data_sources * 20))
        
        return {
            'level': level,
            'score': min(score, max_score),
            'confidence': confidence,
            'threat_count': threat_count,
            'risk_factors': risk_factors
        }
    
    def _generate_detailed_findings(self, analysis_data: Dict[str, Any]) -> Dict[str, str]:
        """Detaylı bulgular oluştur"""
        findings = {}
        
        # VirusTotal findings
        vt_data = analysis_data.get('virustotal_data', {})
        if vt_data and 'error' not in vt_data:
            malicious = vt_data.get('malicious_count', 0)
            suspicious = vt_data.get('suspicious_count', 0)
            clean = vt_data.get('clean_count', 0)
            
            analysis = f"""**VirusTotal Güvenlik Analizi:**

🔍 **Tarama Sonuçları:**
• Zararlı tespit: {malicious} motor
• Şüpheli tespit: {suspicious} motor  
• Temiz tespit: {clean} motor

🚨 **Risk Değerlendirmesi:**
{self._get_vt_risk_assessment(malicious, suspicious)}

📊 **Güvenilirlik:** VirusTotal dünya çapında en güvenilir antivirus motoru"""
            findings['virustotal_data'] = analysis
        
        # URLScan findings  
        urlscan_data = analysis_data.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            mal_domains = urlscan_data.get('malicious_domains', 0)
            sus_domains = urlscan_data.get('suspicious_domains', 0)
            
            analysis = f"""**URLScan Ağ Analizi:**

🌐 **Domain İncelemesi:**
• Zararlı domain: {mal_domains} tespit
• Şüpheli domain: {sus_domains} tespit

🔒 **Ağ Güvenliği:**
{self._get_urlscan_risk_assessment(mal_domains, sus_domains)}

📡 **Kaynak:** URLScan.io global ağ istihbaratı"""
            findings['urlscan_data'] = analysis
        
        # AbuseIPDB findings
        abuse_data = analysis_data.get('abuseipdb_data', {})
        if abuse_data and 'error' not in abuse_data:
            confidence = abuse_data.get('abuse_confidence', 0)
            reports = abuse_data.get('total_reports', 0)
            categories = abuse_data.get('abuse_categories', [])
            
            analysis = f"""**AbuseIPDB Kötüye Kullanım Analizi:**

⚠️ **Kötüye Kullanım Değerlendirmesi:**
• Güven skoru: %{confidence}
• Toplam rapor: {reports}
• Kategoriler: {', '.join(categories) if categories else 'Belirtilmemiş'}

🛡️ **Güvenlik Durumu:**
{self._get_abuse_risk_assessment(confidence, reports)}

🌍 **Veri Kaynağı:** Küresel kötüye kullanım raporları"""
            findings['abuseipdb_data'] = analysis
        
        return findings
    
    def _generate_security_recommendations(self, risk_assessment: Dict[str, Any], analysis_data: Dict[str, Any]) -> List[str]:
        """Güvenlik önerileri oluştur"""
        recommendations = []
        level = risk_assessment['level']
        
        if level == "CRITICAL":
            recommendations.extend([
                "🚨 ACİL: Bu hedeften uzak durun",
                "🛡️ Güvenlik duvarı kuralları güncelleyin",
                "🔍 Sistem taraması yapın",
                "📞 IT güvenlik ekibi ile iletişime geçin"
            ])
        elif level == "HIGH":
            recommendations.extend([
                "⚠️ Dikkatli olun ve tıklamayın",
                "🔐 Ek güvenlik önlemleri alın",
                "🧹 Antivirus tarama yapın",
                "📧 Şüpheli e-postaları bildirin"
            ])
        elif level == "MEDIUM":
            recommendations.extend([
                "🤔 Temkinli yaklaşın",
                "🔍 Ek araştırma yapın",
                "📋 Güvenlik politikalarını gözden geçirin"
            ])
        else:
            recommendations.extend([
                "✅ Normal güvenlik önlemleri yeterli",
                "🔄 Düzenli güncellemeleri takip edin",
                "🛡️ Güvenlik yazılımını aktif tutun"
            ])
        
        return recommendations
    
    def _generate_threat_intelligence(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Tehdit istihbaratı oluştur"""
        intel = {
            'threat_types': [],
            'attack_vectors': [],
            'geographical_info': {},
            'temporal_analysis': {}
        }
        
        # Threat type analysis
        vt_data = analysis_data.get('virustotal_data', {})
        if vt_data and vt_data.get('malicious_count', 0) > 0:
            intel['threat_types'].append('Malware/Virus')
            intel['attack_vectors'].append('Dosya tabanlı saldırı')
        
        urlscan_data = analysis_data.get('urlscan_data', {})
        if urlscan_data and urlscan_data.get('malicious_domains', 0) > 0:
            intel['threat_types'].append('Zararlı ağ trafiği')
            intel['attack_vectors'].append('Ağ tabanlı saldırı')
        
        abuse_data = analysis_data.get('abuseipdb_data', {})
        if abuse_data and abuse_data.get('abuse_confidence', 0) > 50:
            intel['threat_types'].append('Kötüye kullanım')
            intel['attack_vectors'].append('IP tabanlı saldırı')
        
        return intel
    
    def _format_comprehensive_report(self, target: str, risk_assessment: Dict[str, Any], 
                                   findings: Dict[str, str], recommendations: List[str], 
                                   threat_intel: Dict[str, Any]) -> str:
        """Kapsamlı rapor formatla"""
        
        timestamp = datetime.now().strftime('%d.%m.%Y %H:%M')
        
        report = f"""# 🔍 KAPSAMLI GÜVENLİK ANALİZ RAPORU

**Hedef:** {target}  
**Analiz Tarihi:** {timestamp}  
**Analiz Yöntemi:** Gelişmiş Kural Tabanlı Sistem

---

## 🚨 GENEL RİSK DEĞERLENDİRMESİ

**Risk Seviyesi:** {risk_assessment['level']}  
**Risk Skoru:** {risk_assessment['score']}/100  
**Güven Oranı:** %{risk_assessment['confidence']}  
**Tespit Edilen Tehdit:** {risk_assessment['threat_count']}

---

## 📊 DETAYLI BULGULAR

{chr(10).join(findings.values())}

---

## 🛡️ GÜVENLİK ÖNERİLERİ

{chr(10).join([f"• {rec}" for rec in recommendations])}

---

## 🎯 TEHDİT İSTİHBARATI

**Tespit Edilen Tehdit Türleri:**
{chr(10).join([f"• {threat}" for threat in threat_intel['threat_types']]) if threat_intel['threat_types'] else "• Kritik tehdit tespit edilmedi"}

**Potansiyel Saldırı Vektörleri:**
{chr(10).join([f"• {vector}" for vector in threat_intel['attack_vectors']]) if threat_intel['attack_vectors'] else "• Bilinen saldırı vektörü yok"}

---

## 📈 SONUÇ VE ÖNERİLER

{self._get_final_conclusion(risk_assessment['level'], risk_assessment['score'])}

---

*Bu rapor gelişmiş kural tabanlı analiz sistemi ile oluşturulmuştur. AI analiz sistemi mevcut olmadığı durumlarda kapsamlı güvenlik değerlendirmesi sağlar.*"""

        return report
    
    def _get_vt_risk_assessment(self, malicious: int, suspicious: int) -> str:
        """VirusTotal risk değerlendirmesi"""
        if malicious >= 5:
            return "🚨 YÜKSEK RİSK: Çoklu antivirus motoru zararlı tespit etti"
        elif malicious >= 2:
            return "⚠️ ORTA RİSK: Birden fazla motor zararlı işaretledi"
        elif malicious >= 1:
            return "🟡 DÜŞÜK RİSK: Tek motor zararlı tespit etti"
        elif suspicious >= 5:
            return "🟡 ŞÜPHELİ: Çoklu motor şüpheli buldu"
        else:
            return "✅ TEMİZ: Zararlı içerik tespit edilmedi"
    
    def _get_urlscan_risk_assessment(self, mal_domains: int, sus_domains: int) -> str:
        """URLScan risk değerlendirmesi"""
        if mal_domains >= 3:
            return "🚨 YÜKSEK RİSK: Çoklu zararlı domain tespit edildi"
        elif mal_domains >= 1:
            return "⚠️ ORTA RİSK: Zararlı domain bağlantısı var"
        elif sus_domains >= 3:
            return "🟡 DİKKAT: Şüpheli domain aktivitesi"
        else:
            return "✅ TEMİZ: Zararlı ağ aktivitesi yok"
    
    def _get_abuse_risk_assessment(self, confidence: int, reports: int) -> str:
        """AbuseIPDB risk değerlendirmesi"""
        if confidence >= 75:
            return "🚨 YÜKSEK RİSK: Yoğun kötüye kullanım raporu"
        elif confidence >= 50:
            return "⚠️ ORTA RİSK: Önemli kötüye kullanım geçmişi"
        elif confidence >= 25:
            return "🟡 DİKKAT: Sınırlı kötüye kullanım raporu"
        elif reports > 0:
            return "ℹ️ BİLGİ: Az sayıda rapor var"
        else:
            return "✅ TEMİZ: Kötüye kullanım geçmişi yok"
    
    def _get_final_conclusion(self, level: str, score: int) -> str:
        """Final sonuç"""
        if level == "CRITICAL":
            return "🚨 **URGENT:** Bu hedef kritik güvenlik riski taşıyor. Derhal uzak durun ve IT ekibi ile iletişime geçin."
        elif level == "HIGH":
            return "⚠️ **DİKKAT:** Yüksek risk tespit edildi. Ek güvenlik önlemleri alın ve sistem taraması yapın."
        elif level == "MEDIUM":
            return "🟡 **TEMKINLI:** Orta seviye risk. Ek araştırma yapın ve güvenlik önlemlerini gözden geçirin."
        elif level == "LOW":
            return "ℹ️ **BİLGİ:** Düşük risk seviyesi. Normal güvenlik önlemleri ile devam edin."
        else:
            return "✅ **GÜVENLI:** Minimal risk. Rutin güvenlik önlemleri yeterli."
