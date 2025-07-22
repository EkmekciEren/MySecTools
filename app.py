from flask import Flask, request, jsonify, render_template, send_file, make_response
from flask_cors import CORS
import os
import logging
import json
import io
import csv
from datetime import datetime
from dotenv import load_dotenv

# For PDF generation
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white, red, green, orange
    from reportlab.platypus import PageBreak, Image
    from reportlab.graphics.shapes import Drawing, Rect, Circle
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    PDF_AVAILABLE = True
    print("ReportLab successfully imported for PDF generation")
except ImportError as e:
    PDF_AVAILABLE = False
    print(f"Warning: ReportLab not installed. PDF generation will be unavailable. Error: {e}")

from services.security_analyzer import SecurityAnalyzer
from utils.cache_manager import CacheManager
from utils.validators import validate_target
from utils.response_formatter import format_response

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize security analyzer
security_analyzer = SecurityAnalyzer()

# Initialize cache manager
cache_manager = CacheManager()

@app.route('/')
def index():
    """Serve the main page"""
    return render_template('index.html')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """
    Main analysis endpoint
    Usage: /analyze?target=example.com or POST with JSON
    """
    try:
        # Get target from query parameter or JSON body
        if request.method == 'GET':
            target = request.args.get('target')
            api_keys = None
        else:
            data = request.get_json()
            target = data.get('target') if data else None
            api_keys = data.get('api_keys') if data else None
        
        if not target:
            return jsonify({
                'error': 'Target parameter is required',
                'usage': '/analyze?target=example.com'
            }), 400
        
        # Validate target format
        validation_result = validate_target(target)
        if not validation_result['valid']:
            return jsonify({
                'error': f'Invalid target format: {validation_result["message"]}'
            }), 400
        
        logger.info(f"Starting analysis for target: {target}")
        
        # Create a new analyzer instance with custom API keys if provided
        if api_keys:
            from services.security_analyzer import SecurityAnalyzer
            custom_analyzer = SecurityAnalyzer(api_keys=api_keys)
            analysis_result = custom_analyzer.analyze(target)
        else:
            # Use default analyzer with environment variables
            analysis_result = security_analyzer.analyze(target)
        
        # Format response
        response = format_response(target, analysis_result)
        
        logger.info(f"Analysis completed for target: {target}")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@app.route('/test-api-keys', methods=['POST'])
def test_api_keys():
    """
    Test API keys without running full analysis
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        api_keys = data.get('api_keys', {})
        test_results = {}
        
        # Test each API key individually
        from services.api_clients.urlscan_client import URLScanClient
        from services.api_clients.virustotal_client import VirusTotalClient  
        from services.api_clients.abuseipdb_client import AbuseIPDBClient
        from services.ai_analyzer import AIAnalyzer
        
        # Test URLScan API
        if 'urlscan_api_key' in api_keys:
            try:
                client = URLScanClient(api_keys['urlscan_api_key'])
                # Simple validation - check if key format is valid
                if len(api_keys['urlscan_api_key']) >= 32:
                    test_results['urlscan'] = {'status': 'valid_format', 'message': 'API anahtarı formatı geçerli'}
                else:
                    test_results['urlscan'] = {'status': 'invalid_format', 'message': 'API anahtarı formatı geçersiz'}
            except Exception as e:
                test_results['urlscan'] = {'status': 'error', 'message': str(e)}
        
        # Test VirusTotal API
        if 'virustotal_api_key' in api_keys:
            try:
                client = VirusTotalClient(api_keys['virustotal_api_key'])
                # Simple validation - check if key format is valid
                if len(api_keys['virustotal_api_key']) >= 32:
                    test_results['virustotal'] = {'status': 'valid_format', 'message': 'API anahtarı formatı geçerli'}
                else:
                    test_results['virustotal'] = {'status': 'invalid_format', 'message': 'API anahtarı formatı geçersiz'}
            except Exception as e:
                test_results['virustotal'] = {'status': 'error', 'message': str(e)}
        
        # Test AbuseIPDB API
        if 'abuseipdb_api_key' in api_keys:
            try:
                client = AbuseIPDBClient(api_keys['abuseipdb_api_key'])
                # Simple validation - check if key format is valid
                if len(api_keys['abuseipdb_api_key']) >= 32:
                    test_results['abuseipdb'] = {'status': 'valid_format', 'message': 'API anahtarı formatı geçerli'}
                else:
                    test_results['abuseipdb'] = {'status': 'invalid_format', 'message': 'API anahtarı formatı geçersiz'}
            except Exception as e:
                test_results['abuseipdb'] = {'status': 'error', 'message': str(e)}
        
        # Test OpenAI API  
        if 'openai_api_key' in api_keys:
            try:
                analyzer = AIAnalyzer(api_keys['openai_api_key'])
                # Simple validation - check if key format is valid
                if api_keys['openai_api_key'].startswith('sk-'):
                    test_results['openai'] = {'status': 'valid_format', 'message': 'API anahtarı formatı geçerli'}
                else:
                    test_results['openai'] = {'status': 'invalid_format', 'message': 'API anahtarı formatı geçersiz (sk- ile başlamalı)'}
            except Exception as e:
                test_results['openai'] = {'status': 'error', 'message': str(e)}
        
        return jsonify({
            'status': 'success',
            'test_results': test_results,
            'message': 'API anahtarları test edildi'
        })
        
    except Exception as e:
        logger.error(f"API key test error: {str(e)}")
        return jsonify({
            'error': 'API anahtarı testi başarısız',
            'message': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Security Analysis API is running'
    })

@app.route('/cache/stats', methods=['GET'])
def cache_stats():
    """Get cache statistics and rate limit status"""
    try:
        stats = cache_manager.get_cache_stats()
        
        # Get rate limit status from AI analyzer
        from services.ai_analyzer import AIAnalyzer
        ai_analyzer = AIAnalyzer()
        rate_limit_status = ai_analyzer.rate_limit_manager.get_status()
        
        return jsonify({
            'status': 'success',
            'cache_stats': stats,
            'rate_limit_status': rate_limit_status
        })
    except Exception as e:
        logger.error(f"Cache stats error: {str(e)}")
        return jsonify({
            'error': 'Cache istatistikleri alınamadı',
            'message': str(e)
        }), 500

@app.route('/cache/clear', methods=['POST'])
def clear_cache():
    """Clear cache files"""
    try:
        cleared_count = cache_manager.clear_cache()
        return jsonify({
            'status': 'success',
            'message': f'{cleared_count} cache dosyası temizlendi',
            'cleared_files': cleared_count
        })
    except Exception as e:
        logger.error(f"Cache clear error: {str(e)}")
        return jsonify({
            'error': 'Cache temizlenemedi',
            'message': str(e)
        }), 500

@app.route('/test-export', methods=['GET'])
def test_export():
    """Test endpoint for export functionality"""
    return jsonify({
        'message': 'Export endpoints are working',
        'available_endpoints': ['/export/pdf', '/export/excel', '/export/json'],
        'status': 'OK'
    })

@app.route('/export/pdf', methods=['POST'])
def export_pdf():
    """Export analysis results as comprehensive PDF with charts and AI analysis"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        if not PDF_AVAILABLE:
            return jsonify({'error': 'PDF generation not available. ReportLab package not properly installed.'}), 500
        
        # Create PDF in memory
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=50, bottomMargin=50)
        styles = getSampleStyleSheet()
        story = []
        
        # Register Turkish-compatible font
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.fonts import addMapping
        
        try:
            # Try to use DejaVu Sans which supports Turkish characters
            pdfmetrics.registerFont(TTFont('DejaVu', '/System/Library/Fonts/Arial.ttf'))
            pdfmetrics.registerFont(TTFont('DejaVu-Bold', '/System/Library/Fonts/Arial Bold.ttf'))
            addMapping('DejaVu', 0, 0, 'DejaVu')
            addMapping('DejaVu', 1, 0, 'DejaVu-Bold')
            turkish_font = 'DejaVu'
            turkish_font_bold = 'DejaVu-Bold'
        except:
            try:
                # Fallback to Helvetica which has better Unicode support in newer versions
                turkish_font = 'Helvetica'
                turkish_font_bold = 'Helvetica-Bold'
            except:
                # Last fallback
                turkish_font = 'Times-Roman'
                turkish_font_bold = 'Times-Bold'
        
        # Custom styles with Turkish font support
        title_style = styles['Title'].clone('CustomTitle')
        title_style.fontSize = 24
        title_style.textColor = colors.Color(26/255, 26/255, 26/255)  # #1a1a1a
        title_style.spaceAfter = 30
        title_style.fontName = turkish_font_bold
        
        heading_style = styles['Heading1'].clone('CustomHeading')
        heading_style.fontSize = 16
        heading_style.textColor = colors.Color(51/255, 51/255, 51/255)  # #333333
        heading_style.spaceBefore = 20
        heading_style.spaceAfter = 10
        heading_style.fontName = turkish_font_bold
        
        normal_style = styles['Normal'].clone('CustomNormal')
        normal_style.fontSize = 12
        normal_style.textColor = colors.Color(68/255, 68/255, 68/255)  # #444444
        normal_style.fontName = turkish_font
        
        # Title and Header
        title = Paragraph("SecApp Güvenlik Analiz Raporu", title_style)
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Analysis Summary Box
        summary_data = [
            ['Hedef', data.get('target', 'Bilinmiyor')],
            ['Analiz Tarihi', datetime.now().strftime('%d.%m.%Y %H:%M')],
            ['Risk Seviyesi', _get_risk_level_tr(data.get('risk_level', 'UNKNOWN'))],
            ['Risk Skoru', f"{data.get('risk_score', 0)}/100"],
            ['Güven Oranı', f"{data.get('confidence', 0):.1f}%"]
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.Color(248/255, 249/255, 250/255)),  # #f8f9fa
            ('BACKGROUND', (1, 0), (1, -1), colors.white),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), turkish_font_bold),
            ('FONTNAME', (1, 0), (1, -1), turkish_font),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.Color(222/255, 226/255, 230/255)),  # #dee2e6
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 30))
        
        # Data Sources Status
        story.append(Paragraph("Veri Kaynakları Durumu", heading_style))
        sources = data.get('sources', {})
        
        # Detailed source status
        source_data = [['Veri Kaynağı', 'Durum']]
        for source, status in sources.items():
            status_text = '✓ Başarılı' if status else '✗ Başarısız'
            source_data.append([source, status_text])
        
        source_table = Table(source_data, colWidths=[2.5*inch, 2.5*inch])
        source_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(52/255, 58/255, 64/255)),  # #343a40
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), turkish_font_bold),
            ('FONTNAME', (0, 1), (-1, -1), turkish_font),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('GRID', (0, 0), (-1, -1), 1, colors.Color(222/255, 226/255, 230/255)),  # #dee2e6
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.Color(248/255, 249/255, 250/255), colors.white])
        ]))
        story.append(source_table)
        story.append(Spacer(1, 20))
        
        # AI Analysis Section
        full_results = data.get('full_results', {})
        ai_final_analysis = full_results.get('ai_final_analysis', '')
        
        if ai_final_analysis and ai_final_analysis.strip():
            story.append(Paragraph("Yapay Zeka Analizi", heading_style))
            
            # Split AI analysis into sections
            ai_sections = ai_final_analysis.split('\n\n')
            for section in ai_sections:
                if section.strip():
                    # Handle headers (lines starting with #)
                    if section.strip().startswith('#'):
                        header_text = section.strip().replace('#', '').strip()
                        header_para = Paragraph(header_text, heading_style)
                        story.append(header_para)
                    else:
                        # Regular text
                        ai_para = Paragraph(section.strip(), normal_style)
                        story.append(ai_para)
            
            story.append(Spacer(1, 20))
        
        # Technical Details Section
        story.append(Paragraph("Teknik Detaylar", heading_style))
        
        # URLScan results
        urlscan_data = full_results.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            story.append(Paragraph("URLScan.io Sonuçları:", styles['Heading2']))
            urlscan_details = [
                ['Zararlı Domain', str(urlscan_data.get('malicious_domains', 0))],
                ['Şüpheli Domain', str(urlscan_data.get('suspicious_domains', 0))],
                ['IP Adresi', urlscan_data.get('ip', 'N/A')],
                ['Ülke', urlscan_data.get('country', 'N/A')],
                ['Sayfa Durumu', urlscan_data.get('page_status', 'N/A')]
            ]
            
            urlscan_table = Table(urlscan_details, colWidths=[2*inch, 3*inch])
            urlscan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.Color(227/255, 242/255, 253/255)),  # #e3f2fd
                ('GRID', (0, 0), (-1, -1), 1, colors.Color(222/255, 226/255, 230/255)),  # #dee2e6
                ('FONTNAME', (0, 0), (0, -1), turkish_font_bold),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 8)
            ]))
            story.append(urlscan_table)
            story.append(Spacer(1, 15))
        
        # VirusTotal results
        virustotal_data = full_results.get('virustotal_data', {})
        if virustotal_data and 'error' not in virustotal_data:
            story.append(Paragraph("VirusTotal Sonuçları:", styles['Heading2']))
            vt_details = [
                ['Zararlı Tespit', f"{virustotal_data.get('malicious_count', 0)}/{virustotal_data.get('total_engines', 0)}"],
                ['Şüpheli Tespit', f"{virustotal_data.get('suspicious_count', 0)}/{virustotal_data.get('total_engines', 0)}"],
                ['Temiz Tespit', f"{virustotal_data.get('clean_count', 0)}/{virustotal_data.get('total_engines', 0)}"],
                ['Reputation Skoru', str(virustotal_data.get('reputation', 0))],
                ['Hedef Tipi', virustotal_data.get('target_type', 'N/A')]
            ]
            
            vt_table = Table(vt_details, colWidths=[2*inch, 3*inch])
            vt_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.Color(255/255, 243/255, 224/255)),  # #fff3e0
                ('GRID', (0, 0), (-1, -1), 1, colors.Color(222/255, 226/255, 230/255)),  # #dee2e6
                ('FONTNAME', (0, 0), (0, -1), turkish_font_bold),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 8)
            ]))
            story.append(vt_table)
            story.append(Spacer(1, 15))
        
        # AbuseIPDB results
        abuseipdb_data = full_results.get('abuseipdb_data', {})
        if abuseipdb_data and 'error' not in abuseipdb_data:
            story.append(Paragraph("AbuseIPDB Sonuçları:", styles['Heading2']))
            abuse_details = [
                ['IP Adresi', abuseipdb_data.get('ip_address', 'N/A')],
                ['Kötüye Kullanım Güveni', f"%{abuseipdb_data.get('abuse_confidence', 0)}"],
                ['Toplam Rapor', str(abuseipdb_data.get('total_reports', 0))],
                ['Risk Seviyesi', abuseipdb_data.get('risk_level', 'N/A')],
                ['ISP', abuseipdb_data.get('isp', 'N/A')],
                ['Ülke', abuseipdb_data.get('country_name', 'N/A')]
            ]
            
            abuse_table = Table(abuse_details, colWidths=[2*inch, 3*inch])
            abuse_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.Color(255/255, 235/255, 238/255)),  # #ffebee
                ('GRID', (0, 0), (-1, -1), 1, colors.Color(222/255, 226/255, 230/255)),  # #dee2e6
                ('FONTNAME', (0, 0), (0, -1), turkish_font_bold),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 8)
            ]))
            story.append(abuse_table)
        
        # Footer
        story.append(Spacer(1, 20))
        footer = Paragraph(
            f"Bu rapor SecApp tarafından {datetime.now().strftime('%d.%m.%Y %H:%M')} tarihinde otomatik olarak oluşturulmuştur.",
            normal_style
        )
        story.append(footer)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Return PDF file
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=secapp_rapor_{datetime.now().strftime("%Y%m%d_%H%M")}.pdf'
        
        return response
        
    except Exception as e:
        logger.error(f"PDF export error: {str(e)}")
        return jsonify({'error': 'PDF generation failed', 'message': str(e)}), 500

def _get_risk_level_tr(risk_level):
    """Convert English risk level to Turkish"""
    risk_map = {
        'LOW': 'Düşük',
        'MEDIUM': 'Orta', 
        'HIGH': 'Yüksek',
        'CRITICAL': 'Kritik',
        'UNKNOWN': 'Bilinmiyor'
    }
    return risk_map.get(risk_level, 'Bilinmiyor')

@app.route('/export/excel', methods=['POST'])
def export_excel():
    """Export analysis results as enhanced CSV (Excel compatible) with detailed data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        logger.info(f"Excel export data received: {data}")
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Report Header
        writer.writerow(['=== SECAPP GÜVENLİK ANALİZ RAPORU ==='])
        writer.writerow([])
        
        # Basic Information
        writer.writerow(['TEMEL BİLGİLER'])
        writer.writerow(['Alan', 'Değer'])
        writer.writerow(['Hedef', data.get('target', 'Bilinmiyor')])
        writer.writerow(['Tarih', datetime.now().strftime('%d.%m.%Y %H:%M')])
        writer.writerow(['Risk Seviyesi', _get_risk_level_tr(data.get('risk_level', 'UNKNOWN'))])
        writer.writerow(['Risk Skoru', f"{data.get('risk_score', 0)}/100"])
        writer.writerow(['Güven Oranı', f"{data.get('confidence', 0):.1f}%"])
        writer.writerow([])
        
        # Data Sources Status
        writer.writerow(['VERİ KAYNAKLARI DURUMU'])
        writer.writerow(['Kaynak', 'Durum'])
        sources = data.get('sources', {})
        for source, status in sources.items():
            status_text = 'Başarılı' if status else 'Başarısız'
            writer.writerow([source, status_text])
        writer.writerow([])
        
        # Get full results for detailed analysis
        full_results = data.get('full_results', {})
        
        # URLScan.io Details
        urlscan_data = full_results.get('urlscan_data', {})
        if urlscan_data and 'error' not in urlscan_data:
            writer.writerow(['URLSCAN.IO DETAYLAR'])
            writer.writerow(['Metrik', 'Değer'])
            writer.writerow(['Zararlı Domain Sayısı', urlscan_data.get('malicious_domains', 0)])
            writer.writerow(['Şüpheli Domain Sayısı', urlscan_data.get('suspicious_domains', 0)])
            writer.writerow(['IP Adresi', urlscan_data.get('ip', 'N/A')])
            writer.writerow(['Ülke', urlscan_data.get('country', 'N/A')])
            writer.writerow(['Sayfa Durumu', urlscan_data.get('page_status', 'N/A')])
            writer.writerow(['Server', urlscan_data.get('server', 'N/A')])
            writer.writerow([])
        
        # VirusTotal Details
        virustotal_data = full_results.get('virustotal_data', {})
        if virustotal_data and 'error' not in virustotal_data:
            writer.writerow(['VIRUSTOTAL DETAYLAR'])
            writer.writerow(['Metrik', 'Değer'])
            writer.writerow(['Zararlı Tespit', f"{virustotal_data.get('malicious_count', 0)}/{virustotal_data.get('total_engines', 0)}"])
            writer.writerow(['Şüpheli Tespit', f"{virustotal_data.get('suspicious_count', 0)}/{virustotal_data.get('total_engines', 0)}"])
            writer.writerow(['Temiz Tespit', f"{virustotal_data.get('clean_count', 0)}/{virustotal_data.get('total_engines', 0)}"])
            writer.writerow(['Reputation Skoru', virustotal_data.get('reputation', 0)])
            writer.writerow(['Hedef Tipi', virustotal_data.get('target_type', 'N/A')])
            writer.writerow([])
        
        # AbuseIPDB Details
        abuseipdb_data = full_results.get('abuseipdb_data', {})
        if abuseipdb_data and 'error' not in abuseipdb_data:
            writer.writerow(['ABUSEIPDB DETAYLAR'])
            writer.writerow(['Metrik', 'Değer'])
            writer.writerow(['IP Adresi', abuseipdb_data.get('ip_address', 'N/A')])
            writer.writerow(['Kötüye Kullanım Güveni (%)', abuseipdb_data.get('abuse_confidence', 0)])
            writer.writerow(['Toplam Rapor Sayısı', abuseipdb_data.get('total_reports', 0)])
            writer.writerow(['Risk Seviyesi', abuseipdb_data.get('risk_level', 'N/A')])
            writer.writerow(['Ülke', abuseipdb_data.get('country_name', 'N/A')])
            writer.writerow(['ISP', abuseipdb_data.get('isp', 'N/A')])
            writer.writerow(['Beyaz Listede', 'Evet' if abuseipdb_data.get('is_whitelisted') else 'Hayır'])
            writer.writerow([])
        
        # AI Analysis
        ai_final_analysis = full_results.get('ai_final_analysis', '')
        if ai_final_analysis and ai_final_analysis.strip():
            writer.writerow(['YAPAY ZEKA ANALİZİ'])
            writer.writerow([''])
            
            # Split AI analysis into lines and process
            ai_lines = ai_final_analysis.split('\n')
            for line in ai_lines:
                if line.strip():
                    clean_line = line.strip().replace('#', '').strip()
                    if clean_line:
                        writer.writerow([clean_line])
            writer.writerow([])
        
        # Summary Statistics
        writer.writerow(['ÖZET İSTATİSTİKLER'])
        writer.writerow(['Metrik', 'Değer'])
        
        total_sources = len(sources)
        successful_sources = sum(1 for status in sources.values() if status)
        total_threats = 0
        
        if urlscan_data and 'error' not in urlscan_data:
            total_threats += urlscan_data.get('malicious_domains', 0) + urlscan_data.get('suspicious_domains', 0)
        if virustotal_data and 'error' not in virustotal_data:
            total_threats += virustotal_data.get('malicious_count', 0)
        if abuseipdb_data and 'error' not in abuseipdb_data:
            if abuseipdb_data.get('abuse_confidence', 0) > 25:
                total_threats += 1
        
        writer.writerow(['Toplam Veri Kaynağı', total_sources])
        writer.writerow(['Başarılı Kaynak', successful_sources])
        writer.writerow(['Toplam Tehdit Tespiti', total_threats])
        writer.writerow(['Güvenlik Skoru', f"{max(0, 100 - (total_threats * 20))}/100"])
        writer.writerow([])
        
        # Report Footer
        writer.writerow(['=== RAPOR SONU ==='])
        writer.writerow([f'Bu rapor SecApp tarafından {datetime.now().strftime("%d.%m.%Y %H:%M")} tarihinde otomatik olarak oluşturulmuştur.'])
        
        # Convert to bytes
        output.seek(0)
        csv_data = output.getvalue().encode('utf-8-sig')  # BOM for Excel compatibility
        
        # Return CSV file
        response = make_response(csv_data)
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename=secapp_rapor_{datetime.now().strftime("%Y%m%d_%H%M")}.csv'
        
        return response
        
    except Exception as e:
        logger.error(f"Excel export error: {str(e)}")
        return jsonify({'error': 'Excel export failed', 'message': str(e)}), 500

@app.route('/export/json', methods=['POST'])
def export_json():
    """Export analysis results as JSON"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Add timestamp
        data['export_timestamp'] = datetime.now().isoformat()
        
        # Convert to JSON
        json_data = json.dumps(data, indent=2, ensure_ascii=False)
        
        # Return JSON file
        response = make_response(json_data)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename=secapp_rapor_{datetime.now().strftime("%Y%m%d_%H%M")}.json'
        
        return response
        
    except Exception as e:
        logger.error(f"JSON export error: {str(e)}")
        return jsonify({'error': 'JSON export failed', 'message': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    debug = os.getenv('DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug)
