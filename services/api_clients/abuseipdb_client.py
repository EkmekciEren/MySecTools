import os
import requests
import logging
from typing import Dict, Any
import ipaddress

logger = logging.getLogger(__name__)

class AbuseIPDBClient:
    """AbuseIPDB API client for IP reputation analysis"""
    
    def __init__(self):
        self.api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.base_url = 'https://api.abuseipdb.com/api/v2'
        self.headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
    
    def analyze(self, target: str) -> Dict[str, Any]:
        """
        Analyze target using AbuseIPDB
        Only works for IP addresses
        
        Args:
            target: IP address to analyze
            
        Returns:
            Analysis results from AbuseIPDB
        """
        if not self.api_key or self.api_key == 'your_abuseipdb_api_key_here':
            return {
                'error': 'AbuseIPDB API key not configured',
                'status': 'skipped'
            }
        
        try:
            # Extract IP if target is URL
            ip_to_analyze = self._extract_ip_from_target(target)
            
            if not ip_to_analyze:
                return {
                    'error': 'No IP address found for AbuseIPDB analysis',
                    'status': 'skipped',
                    'note': 'AbuseIPDB only analyzes IP addresses'
                }
            
            return self._check_ip(ip_to_analyze)
            
        except Exception as e:
            logger.error(f"AbuseIPDB analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _extract_ip_from_target(self, target: str) -> str:
        """Extract IP address from target"""
        # If target is already an IP, return it
        if self._is_ip(target):
            return target
        
        # If target is URL, try to resolve domain to IP
        if target.startswith(('http://', 'https://')):
            try:
                from urllib.parse import urlparse
                import socket
                
                parsed = urlparse(target)
                domain = parsed.netloc
                
                # Try to resolve domain to IP
                ip = socket.gethostbyname(domain)
                return ip
            except Exception as e:
                logger.warning(f"Could not resolve {target} to IP: {str(e)}")
                return None
        
        # If target is domain, try to resolve to IP
        try:
            import socket
            ip = socket.gethostbyname(target)
            return ip
        except Exception as e:
            logger.warning(f"Could not resolve {target} to IP: {str(e)}")
            return None
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _check_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation on AbuseIPDB"""
        try:
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(
                f'{self.base_url}/check',
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._format_abuseipdb_data(data)
            else:
                return {
                    'error': f'AbuseIPDB check failed: {response.status_code}',
                    'response': response.text
                }
                
        except Exception as e:
            return {'error': f'AbuseIPDB check error: {str(e)}'}
    
    def _format_abuseipdb_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format AbuseIPDB data"""
        try:
            ip_data = data.get('data', {})
            
            return {
                'ip_address': ip_data.get('ipAddress'),
                'is_public': ip_data.get('isPublic'),
                'ip_version': ip_data.get('ipVersion'),
                'is_whitelisted': ip_data.get('isWhitelisted'),
                'abuse_confidence': ip_data.get('abuseConfidencePercentage', 0),
                'country_code': ip_data.get('countryCode'),
                'country_name': ip_data.get('countryName'),
                'usage_type': ip_data.get('usageType'),
                'isp': ip_data.get('isp'),
                'domain': ip_data.get('domain'),
                'total_reports': ip_data.get('totalReports', 0),
                'num_distinct_users': ip_data.get('numDistinctUsers', 0),
                'last_reported_at': ip_data.get('lastReportedAt'),
                'reports': ip_data.get('reports', []),
                'risk_level': self._calculate_risk_level(ip_data.get('abuseConfidencePercentage', 0)),
                'raw_data': data
            }
        except Exception as e:
            logger.error(f"Error formatting AbuseIPDB data: {str(e)}")
            return {'error': f'Data formatting error: {str(e)}', 'raw_data': data}
    
    def _calculate_risk_level(self, abuse_confidence: int) -> str:
        """Calculate risk level based on abuse confidence"""
        if abuse_confidence >= 75:
            return 'HIGH'
        elif abuse_confidence >= 25:
            return 'MEDIUM'
        elif abuse_confidence > 0:
            return 'LOW'
        else:
            return 'CLEAN'
