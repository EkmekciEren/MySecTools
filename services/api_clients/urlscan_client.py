import os
import requests
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class URLScanClient:
    """URLScan.io API client for URL analysis"""
    
    def __init__(self):
        self.api_key = os.getenv('URLSCAN_API_KEY')
        self.base_url = 'https://urlscan.io/api/v1'
        self.headers = {
            'API-Key': self.api_key,
            'Content-Type': 'application/json'
        }
    
    def analyze(self, target: str) -> Dict[str, Any]:
        """
        Analyze URL using URLScan.io
        
        Args:
            target: URL to analyze
            
        Returns:
            Analysis results from URLScan.io
        """
        if not self.api_key or self.api_key == 'your_urlscan_api_key_here':
            return {
                'error': 'URLScan API key not configured',
                'status': 'skipped'
            }
        
        try:
            # Submit URL for scanning
            submission_result = self._submit_url(target)
            if 'error' in submission_result:
                return submission_result
            
            # Wait for scan to complete and get results
            scan_uuid = submission_result.get('uuid')
            if scan_uuid:
                return self._get_scan_result(scan_uuid)
            else:
                return {'error': 'Failed to get scan UUID'}
                
        except Exception as e:
            logger.error(f"URLScan analysis error: {str(e)}")
            return {'error': str(e)}
    
    def _submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for scanning"""
        try:
            payload = {
                'url': url,
                'visibility': 'public'
            }
            
            response = requests.post(
                f'{self.base_url}/scan/',
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f'URLScan submission failed: {response.status_code}',
                    'response': response.text
                }
                
        except requests.RequestException as e:
            return {'error': f'URLScan submission request failed: {str(e)}'}
    
    def _get_scan_result(self, uuid: str, max_retries: int = 6) -> Dict[str, Any]:
        """Get scan results by UUID with retry logic"""
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    f'{self.base_url}/result/{uuid}/',
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return self._format_urlscan_data(data)
                elif response.status_code == 404:
                    # Scan still processing, wait and retry
                    if attempt < max_retries - 1:
                        time.sleep(10)
                        continue
                    else:
                        return {'error': 'Scan timeout - results not ready'}
                else:
                    return {
                        'error': f'URLScan result fetch failed: {response.status_code}',
                        'response': response.text
                    }
                    
            except requests.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                return {'error': f'URLScan result request failed: {str(e)}'}
        
        return {'error': 'Max retries exceeded'}
    
    def _format_urlscan_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format URLScan data for analysis"""
        try:
            task = data.get('task', {})
            page = data.get('page', {})
            stats = data.get('stats', {})
            verdicts = data.get('verdicts', {})
            
            return {
                'scan_id': task.get('uuid'),
                'url': task.get('url'),
                'scan_time': task.get('time'),
                'screenshot': task.get('screenshotURL'),
                'page_title': page.get('title'),
                'page_status': page.get('status'),
                'ip': page.get('ip'),
                'country': page.get('country'),
                'server': page.get('server'),
                'malicious_domains': stats.get('malicious', 0),
                'suspicious_domains': stats.get('suspicious', 0),
                'overall_verdict': verdicts.get('overall', {}),
                'urlscan_verdict': verdicts.get('urlscan', {}),
                'engines_verdict': verdicts.get('engines', {}),
                'raw_data': data
            }
        except Exception as e:
            logger.error(f"Error formatting URLScan data: {str(e)}")
            return {'error': f'Data formatting error: {str(e)}', 'raw_data': data}
