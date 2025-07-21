from typing import Dict, Any
from datetime import datetime

def format_response(target: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format API response according to specification
    
    Args:
        target: Analyzed target
        analysis_result: Analysis results from SecurityAnalyzer
        
    Returns:
        Formatted response dictionary
    """
    response = {
        'target': target,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'analysis_summary': _generate_summary(analysis_result),
        'urlscan_data': analysis_result.get('urlscan_data'),
        'virustotal_data': analysis_result.get('virustotal_data'),
        'abuseipdb_data': analysis_result.get('abuseipdb_data'),
        'ai_step_analyses': analysis_result.get('ai_step_analyses', {}),
        'ai_final_analysis': analysis_result.get('ai_final_analysis', ''),
        'ai_analysis_method': analysis_result.get('ai_analysis_method', 'unknown'),
        'metadata': _generate_metadata(analysis_result)
    }
    
    return response

def _generate_summary(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """Generate analysis summary"""
    summary = {
        'risk_level': 'UNKNOWN',
        'threats_detected': False,
        'data_sources_used': [],
        'confidence_score': 0
    }
    
    threats_count = 0
    total_checks = 0
    
    # Check URLScan results
    urlscan_data = analysis_result.get('urlscan_data', {})
    if urlscan_data and 'error' not in urlscan_data:
        summary['data_sources_used'].append('URLScan.io')
        malicious = urlscan_data.get('malicious_domains', 0)
        suspicious = urlscan_data.get('suspicious_domains', 0)
        if malicious > 0 or suspicious > 0:
            threats_count += 1
        total_checks += 1
    
    # Check VirusTotal results
    virustotal_data = analysis_result.get('virustotal_data', {})
    if virustotal_data and 'error' not in virustotal_data:
        summary['data_sources_used'].append('VirusTotal')
        malicious = virustotal_data.get('malicious_count', 0)
        if malicious > 0:
            threats_count += 1
        total_checks += 1
    
    # Check AbuseIPDB results
    abuseipdb_data = analysis_result.get('abuseipdb_data', {})
    if abuseipdb_data and 'error' not in abuseipdb_data:
        summary['data_sources_used'].append('AbuseIPDB')
        confidence = abuseipdb_data.get('abuse_confidence', 0)
        if confidence > 25:  # Medium risk threshold
            threats_count += 1
        total_checks += 1
    
    # Determine overall risk level
    if threats_count == 0:
        summary['risk_level'] = 'LOW'
    elif threats_count == 1:
        summary['risk_level'] = 'MEDIUM'
    elif threats_count >= 2:
        summary['risk_level'] = 'HIGH'
    
    summary['threats_detected'] = threats_count > 0
    summary['confidence_score'] = (total_checks / 3.0) * 100 if total_checks > 0 else 0
    
    return summary

def _generate_metadata(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """Generate response metadata"""
    metadata = {
        'api_version': '1.0',
        'analysis_duration': 'N/A',
        'data_sources': {
            'urlscan': _get_source_status(analysis_result.get('urlscan_data')),
            'virustotal': _get_source_status(analysis_result.get('virustotal_data')),
            'abuseipdb': _get_source_status(analysis_result.get('abuseipdb_data'))
        }
    }
    
    return metadata

def _get_source_status(data: Dict[str, Any]) -> str:
    """Get status of data source"""
    if not data:
        return 'not_available'
    elif 'error' in data:
        if data.get('status') == 'skipped':
            return 'skipped'
        else:
            return 'error'
    else:
        return 'success'
