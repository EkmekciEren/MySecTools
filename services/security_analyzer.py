import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any

from .api_clients.urlscan_client import URLScanClient
from .api_clients.virustotal_client import VirusTotalClient
from .api_clients.abuseipdb_client import AbuseIPDBClient
from .ai_analyzer import AIAnalyzer

logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    """Main security analysis orchestrator"""
    
    def __init__(self):
        self.urlscan_client = URLScanClient()
        self.virustotal_client = VirusTotalClient()
        self.abuseipdb_client = AbuseIPDBClient()
        self.ai_analyzer = AIAnalyzer()
    
    def analyze(self, target: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis on target
        
        Args:
            target: URL, IP address, or domain to analyze
            
        Returns:
            Dictionary containing all analysis results with step-by-step AI analysis
        """
        logger.info(f"Starting comprehensive analysis for: {target}")
        
        # Collect data from all sources in parallel
        analysis_data = self._collect_security_data(target)
        
        # Generate step-by-step AI analysis
        ai_results = self._generate_step_by_step_ai_analysis(target, analysis_data)
        analysis_data.update(ai_results)
        
        logger.info(f"Analysis completed for: {target}")
        return analysis_data
    
    def _collect_security_data(self, target: str) -> Dict[str, Any]:
        """Collect data from all security APIs in parallel"""
        results = {
            'urlscan_data': None,
            'virustotal_data': None,
            'abuseipdb_data': None
        }
        
        # Define analysis tasks
        tasks = [
            ('urlscan_data', self.urlscan_client.analyze, target),
            ('virustotal_data', self.virustotal_client.analyze, target),
            ('abuseipdb_data', self.abuseipdb_client.analyze, target)
        ]
        
        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_key = {
                executor.submit(task_func, target): key 
                for key, task_func, target in tasks
            }
            
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    results[key] = future.result()
                    logger.info(f"Successfully collected data from {key}")
                except Exception as e:
                    logger.error(f"Error collecting data from {key}: {str(e)}")
                    results[key] = {'error': str(e)}
        
        return results
    
    def _generate_step_by_step_ai_analysis(self, target: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate step-by-step AI analysis of collected data"""
        try:
            ai_results = self.ai_analyzer.analyze_step_by_step(target, analysis_data)
            ai_error_message = ai_results.get('ai_error_message')
            
            # None'ı string'e çevrilmesini önle
            if ai_error_message == "None" or ai_error_message is None:
                ai_error_message = None
                
            return {
                'ai_step_analyses': ai_results.get('step_by_step_analysis', {}),
                'ai_final_analysis': ai_results.get('final_comprehensive_analysis', ''),
                'ai_analysis_method': ai_results.get('analysis_method', 'unknown'),
                'ai_error_message': ai_error_message  # Hata mesajını ilet
            }
        except Exception as e:
            logger.warning(f"AI step-by-step analysis wrapper error: {str(e)}")
            error_str = str(e).lower()
            if 'quota' in error_str or '429' in error_str:
                error_message = "⚠️ AI analiz yapılamadı: OpenAI API kotası aşıldı. Kural tabanlı analiz uygulanıyor..."
            elif 'timeout' in error_str:
                error_message = "⚠️ AI analiz yapılamadı: Bağlantı zaman aşımı. Kural tabanlı analiz uygulanıyor..."
            elif 'authentication' in error_str or 'unauthorized' in error_str:
                error_message = "⚠️ AI analiz yapılamadı: API anahtarı geçersiz. Kural tabanlı analiz uygulanıyor..."
            else:
                error_message = "⚠️ AI analiz yapılamadı: Teknik bir hata oluştu. Kural tabanlı analiz uygulanıyor..."
                
            return {
                'ai_step_analyses': {},
                'ai_final_analysis': f"AI analizi oluşturulurken hata oluştu. Kural tabanlı analiz uygulanıyor.",
                'ai_analysis_method': 'error',
                'ai_error_message': error_message
            }
