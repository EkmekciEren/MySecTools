import os
import time
import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

@dataclass
class RateLimitInfo:
    """OpenAI API rate limit bilgileri"""
    max_requests_per_minute: int = 2      # gpt-4o-mini free tier: 3 RPM (safe: 2)
    max_tokens_per_minute: int = 55000    # gpt-4o-mini free tier: 60,000 TPM (safe: 55,000)
    current_requests: int = 0
    current_tokens: int = 0
    quota_exceeded: bool = False
    reset_time: Optional[datetime] = None
    last_reset: float = 0
    window_start: float = 0
    
    def to_dict(self):
        return asdict(self)

class OpenAIRateLimitManager:
    """OpenAI API Rate Limit yönetimi"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.rate_limit = RateLimitInfo()
        self.rate_limit.window_start = time.time()  # Initialize window_start
        self.request_history: List[Dict] = []
        self.token_history: List[tuple] = []  # (tokens, timestamp) tuples
        self.lock = threading.Lock()
        
        # Updated defaults based on actual OpenAI Free Tier limits
        # gpt-4o-mini Free tier: 3 RPM, 60,000 TPM, 200 RPD (OpenAI official limits)
        self.default_limits = {
            'max_requests_per_minute': 2,     # Safe: 2 RPM (official limit: 3 RPM)
            'max_tokens_per_minute': 55000   # Conservative: 55,000 TPM (official limit: 60,000 TPM)
        }
        
        # Load saved rate limit info
        self._load_rate_limit_cache()
        
    def _load_rate_limit_cache(self):
        """Cache'den rate limit bilgilerini yükle"""
        try:
            cache_file = '.cache/rate_limits.json'
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    self.rate_limit = RateLimitInfo(**data)
                    logger.debug("Rate limit cache loaded")
        except Exception as e:
            logger.warning(f"Rate limit cache load error: {e}")
            self._set_default_limits()
    
    def _save_rate_limit_cache(self):
        """Rate limit bilgilerini cache'e kaydet"""
        try:
            os.makedirs('.cache', exist_ok=True)
            cache_file = '.cache/rate_limits.json'
            with open(cache_file, 'w') as f:
                json.dump(self.rate_limit.to_dict(), f)
        except Exception as e:
            logger.warning(f"Rate limit cache save error: {e}")
    
    def _set_default_limits(self):
        """Varsayılan limitleri ayarla"""
        self.rate_limit.max_requests_per_minute = self.default_limits['max_requests_per_minute']
        self.rate_limit.max_tokens_per_minute = self.default_limits['max_tokens_per_minute']
        self.rate_limit.window_start = time.time()
        logger.info("Using default rate limits")
    
    def update_from_headers(self, response_headers: Dict[str, str]):
        """API response headers'dan rate limit bilgilerini güncelle"""
        try:
            with self.lock:
                # OpenAI response headers'dan bilgi al
                remaining_requests = response_headers.get('x-ratelimit-remaining-requests')
                remaining_tokens = response_headers.get('x-ratelimit-remaining-tokens')
                limit_requests = response_headers.get('x-ratelimit-limit-requests')
                limit_tokens = response_headers.get('x-ratelimit-limit-tokens')
                reset_requests = response_headers.get('x-ratelimit-reset-requests')
                reset_tokens = response_headers.get('x-ratelimit-reset-tokens')
                
                if limit_requests:
                    self.rate_limit.max_requests_per_minute = int(limit_requests)
                if limit_tokens:
                    self.rate_limit.max_tokens_per_minute = int(limit_tokens)
                if remaining_requests:
                    self.rate_limit.current_requests = self.rate_limit.max_requests_per_minute - int(remaining_requests)
                if remaining_tokens:
                    self.rate_limit.current_tokens = self.rate_limit.max_tokens_per_minute - int(remaining_tokens)
                
                # Cache'e kaydet
                self._save_rate_limit_cache()
                logger.debug(f"Rate limits updated from headers: {self.rate_limit}")
                
        except Exception as e:
            logger.warning(f"Error updating rate limits from headers: {e}")
    
    def estimate_tokens(self, text: str) -> int:
        """Token sayısını tahmin et (yaklaşık 4 karakter = 1 token)"""
        return max(1, len(text) // 4)
    
    def can_make_request(self, estimated_tokens: int = 1000) -> tuple[bool, str, int]:
        """
        Request yapılabilir mi kontrol et
        
        Returns:
            (can_proceed, reason, wait_seconds)
        """
        with self.lock:
            now = time.time()
            
            # Pencere sıfırlandı mı kontrol et (1 dakika)
            if now - self.rate_limit.window_start >= 60:
                self.rate_limit.current_requests = 0
                self.rate_limit.current_tokens = 0
                self.rate_limit.window_start = now
                logger.debug("Rate limit window reset")
            
            # Request limiti kontrolü (Free tier 3 RPM için %67 threshold - çok düşük limit!)
            if self.rate_limit.current_requests >= self.rate_limit.max_requests_per_minute * 0.67:
                wait_time = 60 - (now - self.rate_limit.window_start)
                return False, "Request limit exceeded", int(wait_time)
            
            # Token limiti kontrolü (Free tier için %90 threshold - token limiti daha yüksek)
            if self.rate_limit.current_tokens + estimated_tokens >= self.rate_limit.max_tokens_per_minute * 0.90:
                wait_time = 60 - (now - self.rate_limit.window_start)
                return False, "Token limit exceeded", int(wait_time)
            
            return True, "OK", 0
    
    def record_request(self, tokens_used: int):
        """Request kaydını tut"""
        with self.lock:
            self.rate_limit.current_requests += 1
            self.rate_limit.current_tokens += tokens_used
            
            # Request geçmişi tut (debug için)
            self.request_history.append({
                'timestamp': time.time(),
                'tokens': tokens_used,
                'total_requests': self.rate_limit.current_requests,
                'total_tokens': self.rate_limit.current_tokens
            })
            
            # Eski kayıtları temizle (sadece son 100 kayıt)
            if len(self.request_history) > 100:
                self.request_history = self.request_history[-100:]
    
    def _current_window_start(self) -> datetime:
        """Get the start time of the current rate limit window"""
        return datetime.now() - timedelta(minutes=1)
    
    def _clean_old_requests(self):
        """Clean requests older than the current window"""
        current_window = self._current_window_start()
        
        # Remove old requests
        self.request_history = [
            req_time for req_time in self.request_history 
            if req_time >= current_window
        ]
        
        # Update current request count
        self.rate_limit.current_requests = len(self.request_history)
        
        # Clean old token usage
        self.token_history = [
            (tokens, req_time) for tokens, req_time in self.token_history
            if req_time >= current_window
        ]
        
        # Update current token count
        self.rate_limit.current_tokens = sum(tokens for tokens, _ in self.token_history)

    def get_status(self) -> Dict[str, Any]:
        """Get current rate limit status"""
        # Clean old requests first
        self._clean_old_requests()
        
        # Calculate usage percentages safely
        request_usage_percent = 0
        token_usage_percent = 0
        
        if self.rate_limit.max_requests_per_minute > 0:
            request_usage_percent = (self.rate_limit.current_requests / self.rate_limit.max_requests_per_minute) * 100
        
        if self.rate_limit.max_tokens_per_minute > 0:
            token_usage_percent = (self.rate_limit.current_tokens / self.rate_limit.max_tokens_per_minute) * 100
        
        return {
            'current_requests': self.rate_limit.current_requests,
            'max_requests': self.rate_limit.max_requests_per_minute,
            'requests_remaining': max(0, self.rate_limit.max_requests_per_minute - self.rate_limit.current_requests),
            'current_tokens': self.rate_limit.current_tokens,
            'max_tokens': self.rate_limit.max_tokens_per_minute,
            'tokens_remaining': max(0, self.rate_limit.max_tokens_per_minute - self.rate_limit.current_tokens),
            'request_usage_percent': request_usage_percent,
            'token_usage_percent': token_usage_percent,
            'quota_exceeded': self.rate_limit.quota_exceeded,
            'reset_time': self.rate_limit.reset_time.isoformat() if self.rate_limit.reset_time else None,
            'last_updated': datetime.now().isoformat(),
            'window_start': self._current_window_start().isoformat()
        }
    
    def wait_if_needed(self, estimated_tokens: int = 1000) -> bool:
        """Gerekirse bekle, request yapılabilir duruma getir"""
        can_proceed, reason, wait_seconds = self.can_make_request(estimated_tokens)
        
        if not can_proceed and wait_seconds > 0:
            logger.warning(f"Rate limit hit: {reason}, waiting {wait_seconds} seconds")
            time.sleep(wait_seconds + 1)  # Extra buffer
            return True
        
        return can_proceed
