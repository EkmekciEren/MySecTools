import re
import ipaddress
from typing import Dict, Any
from urllib.parse import urlparse

def validate_target(target: str) -> Dict[str, Any]:
    """
    Validate target format (URL, IP, or domain)
    
    Args:
        target: Target string to validate
        
    Returns:
        Dictionary with validation result
    """
    if not target or not isinstance(target, str):
        return {
            'valid': False,
            'message': 'Target must be a non-empty string'
        }
    
    target = target.strip()
    
    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        return _validate_url(target)
    
    # Check if it's an IP address
    if _is_ip_address(target):
        return _validate_ip(target)
    
    # Check if it's a domain
    if _is_domain(target):
        return _validate_domain(target)
    
    return {
        'valid': False,
        'message': 'Target must be a valid URL, IP address, or domain name'
    }

def _validate_url(url: str) -> Dict[str, Any]:
    """Validate URL format"""
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return {
                'valid': False,
                'message': 'Invalid URL format - missing domain'
            }
        
        # Check for malicious patterns
        suspicious_patterns = [
            r'[<>"\']',  # Script injection characters
            r'javascript:',  # JavaScript protocol
            r'data:',  # Data protocol
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return {
                    'valid': False,
                    'message': 'URL contains suspicious patterns'
                }
        
        return {
            'valid': True,
            'type': 'url',
            'message': 'Valid URL format'
        }
        
    except Exception as e:
        return {
            'valid': False,
            'message': f'URL validation error: {str(e)}'
        }

def _validate_ip(ip: str) -> Dict[str, Any]:
    """Validate IP address"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if it's a private IP
        if ip_obj.is_private:
            return {
                'valid': False,
                'message': 'Private IP addresses cannot be analyzed'
            }
        
        # Check if it's localhost
        if ip_obj.is_loopback:
            return {
                'valid': False,
                'message': 'Localhost IP addresses cannot be analyzed'
            }
        
        # Check if it's reserved
        if ip_obj.is_reserved:
            return {
                'valid': False,
                'message': 'Reserved IP addresses cannot be analyzed'
            }
        
        return {
            'valid': True,
            'type': 'ip',
            'version': ip_obj.version,
            'message': f'Valid IPv{ip_obj.version} address'
        }
        
    except ValueError as e:
        return {
            'valid': False,
            'message': f'Invalid IP address: {str(e)}'
        }

def _validate_domain(domain: str) -> Dict[str, Any]:
    """Validate domain name"""
    try:
        # Basic domain format validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
        
        if not re.match(domain_pattern, domain):
            return {
                'valid': False,
                'message': 'Invalid domain name format'
            }
        
        # Check length constraints
        if len(domain) > 253:
            return {
                'valid': False,
                'message': 'Domain name too long (max 253 characters)'
            }
        
        # Check label length constraints
        labels = domain.split('.')
        for label in labels:
            if len(label) == 0 or len(label) > 63:
                return {
                    'valid': False,
                    'message': 'Invalid domain label length'
                }
        
        # Check for localhost
        if domain.lower() in ['localhost', 'localhost.localdomain']:
            return {
                'valid': False,
                'message': 'Localhost domains cannot be analyzed'
            }
        
        return {
            'valid': True,
            'type': 'domain',
            'message': 'Valid domain name'
        }
        
    except Exception as e:
        return {
            'valid': False,
            'message': f'Domain validation error: {str(e)}'
        }

def _is_ip_address(target: str) -> bool:
    """Check if target is an IP address"""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def _is_domain(target: str) -> bool:
    """Check if target looks like a domain name"""
    # Simple check for domain-like string
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$'
    return bool(re.match(domain_pattern, target))
