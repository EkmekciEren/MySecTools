import os
import json
import hashlib
import time
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class CacheManager:
    """Simple file-based cache for AI analysis results"""
    
    def __init__(self, cache_dir: str = None, ttl_seconds: int = 3600):
        """
        Initialize cache manager
        
        Args:
            cache_dir: Directory to store cache files
            ttl_seconds: Time to live for cache entries (default: 1 hour)
        """
        self.cache_dir = cache_dir or os.path.join(os.getcwd(), '.cache', 'ai_analysis')
        self.ttl_seconds = ttl_seconds
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Clean old cache files on startup
        self._cleanup_expired_cache()
    
    def _get_cache_key(self, target: str, analysis_data: Dict[str, Any]) -> str:
        """Generate cache key from target and analysis data"""
        # Create a stable hash from target and relevant analysis data
        cache_data = {
            'target': target,
            'urlscan_summary': self._summarize_urlscan(analysis_data.get('urlscan_data', {})),
            'virustotal_summary': self._summarize_virustotal(analysis_data.get('virustotal_data', {})),
            'abuseipdb_summary': self._summarize_abuseipdb(analysis_data.get('abuseipdb_data', {}))
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def _summarize_urlscan(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of URLScan data for caching"""
        if not data or 'error' in data:
            return {'error': True}
        
        return {
            'malicious_domains': data.get('malicious_domains', 0),
            'suspicious_domains': data.get('suspicious_domains', 0),
            'overall_verdict': data.get('overall_verdict', {}),
            'country': data.get('country'),
            'ip': data.get('ip')
        }
    
    def _summarize_virustotal(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of VirusTotal data for caching"""
        if not data or 'error' in data:
            return {'error': True}
        
        return {
            'malicious_count': data.get('malicious_count', 0),
            'suspicious_count': data.get('suspicious_count', 0),
            'clean_count': data.get('clean_count', 0),
            'total_engines': data.get('total_engines', 0),
            'reputation': data.get('reputation', 0)
        }
    
    def _summarize_abuseipdb(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of AbuseIPDB data for caching"""
        if not data or 'error' in data:
            return {'error': True}
        
        return {
            'abuse_confidence': data.get('abuse_confidence', 0),
            'total_reports': data.get('total_reports', 0),
            'risk_level': data.get('risk_level'),
            'country_name': data.get('country_name')
        }
    
    def get_cache_path(self, cache_key: str) -> str:
        """Get full path for cache file"""
        return os.path.join(self.cache_dir, f"{cache_key}.json")
    
    def get_cached_analysis(self, target: str, analysis_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get cached analysis result if available and not expired
        
        Args:
            target: Target being analyzed
            analysis_data: Analysis data from security APIs
            
        Returns:
            Cached analysis result or None if not found/expired
        """
        try:
            cache_key = self._get_cache_key(target, analysis_data)
            cache_path = self.get_cache_path(cache_key)
            
            if not os.path.exists(cache_path):
                logger.debug(f"No cache found for key: {cache_key}")
                return None
            
            # Check if cache file is expired
            file_age = time.time() - os.path.getmtime(cache_path)
            if file_age > self.ttl_seconds:
                logger.debug(f"Cache expired for key: {cache_key} (age: {file_age:.0f}s)")
                os.remove(cache_path)  # Clean up expired cache
                return None
            
            # Load and return cached data
            with open(cache_path, 'r', encoding='utf-8') as f:
                cached_data = json.load(f)
            
            logger.info(f"Using cached analysis for target: {target}")
            cached_data['cache_info'] = {
                'cached': True,
                'cache_age_seconds': int(file_age),
                'cache_key': cache_key
            }
            
            return cached_data
            
        except Exception as e:
            logger.warning(f"Error reading cache: {str(e)}")
            return None
    
    def save_analysis_to_cache(self, target: str, analysis_data: Dict[str, Any], analysis_result: Dict[str, Any]) -> bool:
        """
        Save analysis result to cache
        
        Args:
            target: Target being analyzed
            analysis_data: Analysis data from security APIs
            analysis_result: AI analysis result to cache
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            cache_key = self._get_cache_key(target, analysis_data)
            cache_path = self.get_cache_path(cache_key)
            
            # Prepare cache data
            cache_data = analysis_result.copy()
            cache_data['cache_metadata'] = {
                'target': target,
                'cached_at': time.time(),
                'cache_key': cache_key,
                'ttl_seconds': self.ttl_seconds
            }
            
            # Save to file
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            
            logger.debug(f"Saved analysis to cache: {cache_key}")
            return True
            
        except Exception as e:
            logger.warning(f"Error saving to cache: {str(e)}")
            return False
    
    def _cleanup_expired_cache(self):
        """Clean up expired cache files"""
        try:
            if not os.path.exists(self.cache_dir):
                return
            
            current_time = time.time()
            cleaned_count = 0
            
            for filename in os.listdir(self.cache_dir):
                if not filename.endswith('.json'):
                    continue
                
                file_path = os.path.join(self.cache_dir, filename)
                try:
                    file_age = current_time - os.path.getmtime(file_path)
                    if file_age > self.ttl_seconds:
                        os.remove(file_path)
                        cleaned_count += 1
                except Exception as e:
                    logger.warning(f"Error cleaning cache file {filename}: {str(e)}")
            
            if cleaned_count > 0:
                logger.info(f"Cleaned {cleaned_count} expired cache files")
                
        except Exception as e:
            logger.warning(f"Error during cache cleanup: {str(e)}")
    
    def clear_cache(self) -> int:
        """
        Clear all cache files
        
        Returns:
            Number of files cleared
        """
        try:
            if not os.path.exists(self.cache_dir):
                return 0
            
            cleared_count = 0
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json'):
                    file_path = os.path.join(self.cache_dir, filename)
                    os.remove(file_path)
                    cleared_count += 1
            
            logger.info(f"Cleared {cleared_count} cache files")
            return cleared_count
            
        except Exception as e:
            logger.error(f"Error clearing cache: {str(e)}")
            return 0
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            if not os.path.exists(self.cache_dir):
                return {'total_files': 0, 'total_size_bytes': 0, 'expired_files': 0}
            
            total_files = 0
            total_size = 0
            expired_files = 0
            current_time = time.time()
            
            for filename in os.listdir(self.cache_dir):
                if not filename.endswith('.json'):
                    continue
                
                file_path = os.path.join(self.cache_dir, filename)
                try:
                    stat = os.stat(file_path)
                    total_files += 1
                    total_size += stat.st_size
                    
                    file_age = current_time - stat.st_mtime
                    if file_age > self.ttl_seconds:
                        expired_files += 1
                        
                except Exception:
                    continue
            
            return {
                'total_files': total_files,
                'total_size_bytes': total_size,
                'expired_files': expired_files,
                'cache_dir': self.cache_dir,
                'ttl_seconds': self.ttl_seconds
            }
            
        except Exception as e:
            logger.error(f"Error getting cache stats: {str(e)}")
            return {'error': str(e)}
