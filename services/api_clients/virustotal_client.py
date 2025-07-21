import os
import requests
import logging
from typing import Dict, Any
import ipaddress

logger = logging.getLogger(__name__)

class VirusTotalClient:
    """VirusTotal API client for URL/IP/Domain analysis"""
    
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {
            'x-apikey': self.api_key
        }
    
    def analyze(self, target: str) -> Dict[str, Any]:
        """
        Analyze target using VirusTotal
        
        Args:
            target: URL, IP, or domain to analyze
            
        Returns:
            Analysis results from VirusTotal
        """
        if not self.api_key or self.api_key == 'your_virustotal_api_key_here':
            return {
                'error': 'VirusTotal API key not configured',
                'status': 'skipped'
            }
        
        try:
            # Determine target type and analyze accordingly
            if self._is_ip(target):
                return self._analyze_ip(target)
            elif target.startswith(('http://', 'https://')):
                return self._analyze_url(target)
            else:
                return self._analyze_domain(target)
                
        except Exception as e:
            logger.error(f"VirusTotal analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL"""
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            response = requests.get(
                f'{self.base_url}/urls/{url_id}',
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._format_url_data(data)
            else:
                return {
                    'error': f'VirusTotal URL analysis failed: {response.status_code}',
                    'response': response.text
                }
                
        except Exception as e:
            return {'error': f'VirusTotal URL analysis error: {str(e)}'}
    
    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain"""
        try:
            response = requests.get(
                f'{self.base_url}/domains/{domain}',
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._format_domain_data(data)
            else:
                return {
                    'error': f'VirusTotal domain analysis failed: {response.status_code}',
                    'response': response.text
                }
                
        except Exception as e:
            return {'error': f'VirusTotal domain analysis error: {str(e)}'}
    
    def _analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze IP address"""
        try:
            response = requests.get(
                f'{self.base_url}/ip_addresses/{ip}',
                headers=self.headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._format_ip_data(data)
            else:
                return {
                    'error': f'VirusTotal IP analysis failed: {response.status_code}',
                    'response': response.text
                }
                
        except Exception as e:
            return {'error': f'VirusTotal IP analysis error: {str(e)}'}
    
    def _format_url_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format URL analysis data"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'target_type': 'url',
                'url': attributes.get('url'),
                'scan_date': attributes.get('last_analysis_date'),
                'malicious_count': stats.get('malicious', 0),
                'suspicious_count': stats.get('suspicious', 0),
                'clean_count': stats.get('harmless', 0),
                'undetected_count': stats.get('undetected', 0),
                'total_engines': sum(stats.values()) if stats else 0,
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {}),
                'engines_analysis': attributes.get('last_analysis_results', {}),
                'raw_data': data
            }
        except Exception as e:
            logger.error(f"Error formatting VirusTotal URL data: {str(e)}")
            return {'error': f'Data formatting error: {str(e)}', 'raw_data': data}
    
    def _format_domain_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format domain analysis data"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'target_type': 'domain',
                'domain': attributes.get('id'),
                'scan_date': attributes.get('last_analysis_date'),
                'malicious_count': stats.get('malicious', 0),
                'suspicious_count': stats.get('suspicious', 0),
                'clean_count': stats.get('harmless', 0),
                'undetected_count': stats.get('undetected', 0),
                'total_engines': sum(stats.values()) if stats else 0,
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {}),
                'whois_date': attributes.get('whois_date'),
                'creation_date': attributes.get('creation_date'),
                'engines_analysis': attributes.get('last_analysis_results', {}),
                'raw_data': data
            }
        except Exception as e:
            logger.error(f"Error formatting VirusTotal domain data: {str(e)}")
            return {'error': f'Data formatting error: {str(e)}', 'raw_data': data}
    
    def _format_ip_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format IP analysis data"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            return {
                'target_type': 'ip',
                'ip': attributes.get('id'),
                'scan_date': attributes.get('last_analysis_date'),
                'malicious_count': stats.get('malicious', 0),
                'suspicious_count': stats.get('suspicious', 0),
                'clean_count': stats.get('harmless', 0),
                'undetected_count': stats.get('undetected', 0),
                'total_engines': sum(stats.values()) if stats else 0,
                'reputation': attributes.get('reputation', 0),
                'country': attributes.get('country'),
                'asn': attributes.get('asn'),
                'as_owner': attributes.get('as_owner'),
                'engines_analysis': attributes.get('last_analysis_results', {}),
                'raw_data': data
            }
        except Exception as e:
            logger.error(f"Error formatting VirusTotal IP data: {str(e)}")
            return {'error': f'Data formatting error: {str(e)}', 'raw_data': data}
