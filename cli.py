#!/usr/bin/env python3
"""
SecApp CLI - Command Line Interface for Security Analysis
"""

import argparse
import json
import sys
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime
import colorama
from colorama import Fore, Back, Style
import textwrap
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging to suppress INFO and WARNING messages
logging.basicConfig(level=logging.ERROR)

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.security_analyzer import SecurityAnalyzer
from utils.validators import validate_target
from utils.response_formatter import format_response
from utils.cache_manager import CacheManager

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class SecAppCLI:
    def __init__(self):
        self.analyzer = SecurityAnalyzer()
        self.cache_manager = CacheManager()
        self.version = "1.2.0"
        
    def print_banner(self):
        """Print the SecApp banner"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                        {Fore.WHITE}SecApp CLI v{self.version}{Fore.CYAN}                        ║
║              {Fore.YELLOW}Advanced Cybersecurity Analysis Platform{Fore.CYAN}              ║
║                   {Fore.GREEN}AI-Powered • Multi-Source{Fore.CYAN}                      ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

    def _check_api_sources(self, data: Dict) -> bool:
        """Check if any API sources are working (not returning configuration errors)"""
        sources = ['urlscan_data', 'virustotal_data', 'abuseipdb_data']
        
        for source in sources:
            if source in data and data[source]:
                source_data = data[source]
                # If data exists and doesn't have a configuration error, consider it working
                if not source_data.get('error') or 'not configured' not in str(source_data.get('error', '')).lower():
                    return True
        
        return False

    def print_colored(self, text: str, color: str = Fore.WHITE, style: str = Style.NORMAL):
        """Print colored text"""
        print(f"{style}{color}{text}{Style.RESET_ALL}")

    def print_status(self, message: str, status: str = "INFO"):
        """Print status message with icon"""
        icons = {
            "INFO": f"{Fore.BLUE}ℹ",
            "SUCCESS": f"{Fore.GREEN}✓",
            "WARNING": f"{Fore.YELLOW}⚠",
            "ERROR": f"{Fore.RED}✗",
            "LOADING": f"{Fore.CYAN}⏳"
        }
        icon = icons.get(status, "•")
        print(f"{icon} {Fore.WHITE}{message}{Style.RESET_ALL}")

    def format_target_info(self, target: str, target_type: str) -> str:
        """Format target information"""
        type_icons = {
            "url": "🌐",
            "domain": "🌍", 
            "ip": "🖥️"
        }
        icon = type_icons.get(target_type, "🎯")
        return f"{icon} {target} ({target_type.upper()})"

    def display_analysis_summary(self, data: Dict):
        """Display analysis summary in a formatted way"""
        if not data.get('analysis_summary'):
            return
            
        summary = data['analysis_summary']
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}{Style.BRIGHT}ANALYSIS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Risk Level
        risk_level = summary.get('risk_level', 'UNKNOWN')
        risk_colors = {
            'MINIMAL': Fore.GREEN,
            'LOW': Fore.LIGHTGREEN_EX,
            'MEDIUM': Fore.YELLOW,
            'HIGH': Fore.LIGHTRED_EX,
            'CRITICAL': Fore.RED
        }
        risk_color = risk_colors.get(risk_level, Fore.WHITE)
        
        print(f"{Fore.WHITE}Risk Level:      {risk_color}{Style.BRIGHT}{risk_level}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Threats Detected: {Fore.RED if summary.get('threats_detected') else Fore.GREEN}{'Yes' if summary.get('threats_detected') else 'No'}")
        print(f"{Fore.WHITE}Confidence:      {Fore.CYAN}{summary.get('confidence_score', 0):.1f}%")
        
        # Data Sources
        if summary.get('data_sources_used'):
            print(f"{Fore.WHITE}Data Sources:    {Fore.LIGHTBLUE_EX}{', '.join(summary['data_sources_used'])}")

    def display_data_sources(self, data: Dict):
        """Display detailed data from sources"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}{Style.BRIGHT}DATA SOURCES DETAILS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        
        sources = [
            ('URLScan.io', 'urlscan_data', '🔍'),
            ('VirusTotal', 'virustotal_data', '🦠'),
            ('AbuseIPDB', 'abuseipdb_data', '🛡️')
        ]
        
        for source_name, key, icon in sources:
            if key in data and data[key]:
                source_data = data[key]
                print(f"\n{Fore.YELLOW}{icon} {source_name}:")
                
                if source_data.get('error'):
                    error_msg = source_data['error']
                    if 'not configured' in error_msg.lower():
                        print(f"  {Fore.YELLOW}🔑 API key not configured")
                        print(f"  {Fore.CYAN}💡 Add your API key to .env file to enable this source")
                    else:
                        print(f"  {Fore.RED}❌ Error: {error_msg}")
                else:
                    self._display_source_details(source_data, key)

    def _display_source_details(self, source_data: Dict, source_type: str):
        """Display details for a specific source"""
        if source_type == 'urlscan_data':
            fields = [
                ('URL', 'url'),
                ('Scan ID', 'scan_id'),
                ('Malicious Domains', 'malicious_domains'),
                ('Suspicious Domains', 'suspicious_domains'),
                ('Country', 'country'),
                ('IP Address', 'ip'),
                ('Page Status', 'page_status')
            ]
        elif source_type == 'virustotal_data':
            fields = [
                ('Target Type', 'target_type'),
                ('Malicious Count', 'malicious_count'),
                ('Suspicious Count', 'suspicious_count'),
                ('Clean Count', 'clean_count'),
                ('Total Engines', 'total_engines'),
                ('Reputation', 'reputation'),
                ('Country', 'country')
            ]
        elif source_type == 'abuseipdb_data':
            fields = [
                ('IP Address', 'ip_address'),
                ('Abuse Confidence', 'abuse_confidence'),
                ('Total Reports', 'total_reports'),
                ('Risk Level', 'risk_level'),
                ('Country', 'country_name'),
                ('ISP', 'isp'),
                ('Whitelisted', 'is_whitelisted')
            ]
        else:
            fields = []
        
        for label, key in fields:
            if key in source_data and source_data[key] is not None:
                value = source_data[key]
                if isinstance(value, bool):
                    value = "Yes" if value else "No"
                print(f"  {Fore.WHITE}{label}: {Fore.LIGHTCYAN_EX}{value}")

    def display_ai_analysis(self, data: Dict):
        """Display AI analysis results"""
        # AI hata mesajını göster (varsa)
        if data.get('ai_error_message'):
            print(f"\n{data['ai_error_message']}")
        
        # Debug: print all AI related keys
        # print(f"DEBUG: AI keys in data: {[k for k in data.keys() if 'ai' in k.lower()]}")
        # print(f"DEBUG: ai_error_message: '{data.get('ai_error_message')}'")
        
        if data.get('ai_final_analysis'):
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.WHITE}{Style.BRIGHT}🤖 AI COMPREHENSIVE ANALYSIS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}")
            
            # Format and display AI analysis
            analysis_text = data['ai_final_analysis']
            # Wrap text to fit terminal width
            wrapped_text = textwrap.fill(analysis_text, width=80)
            print(f"{Fore.WHITE}{wrapped_text}")
        
        if data.get('ai_step_analyses'):
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.WHITE}{Style.BRIGHT}🔍 AI STEP-BY-STEP ANALYSIS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}")
            
            sources = {
                'urlscan_data': '🔍 URLScan.io Analysis',
                'virustotal_data': '🦠 VirusTotal Analysis', 
                'abuseipdb_data': '🛡️ AbuseIPDB Analysis'
            }
            
            for source_key, analysis in data['ai_step_analyses'].items():
                if source_key in sources:
                    print(f"\n{Fore.YELLOW}{sources[source_key]}:")
                    
                    # Check if this is a "no data" message
                    if "verisi mevcut değil" in analysis.lower() or "data not available" in analysis.lower():
                        print(f"{Fore.CYAN}🔑 API key not configured - no data to analyze")
                    else:
                        wrapped_text = textwrap.fill(analysis, width=80)
                        print(f"{Fore.WHITE}{wrapped_text}")

    def save_json_report(self, data: Dict, filename: str):
        """Save analysis results to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.print_status(f"JSON report saved to: {filename}", "SUCCESS")
        except Exception as e:
            self.print_status(f"Failed to save JSON report: {e}", "ERROR")

    def save_text_report(self, data: Dict, filename: str):
        """Save analysis results to text file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"SecApp Security Analysis Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {data.get('target', 'Unknown')}\n")
                f.write("="*60 + "\n\n")
                
                # Summary
                if data.get('analysis_summary'):
                    summary = data['analysis_summary']
                    f.write("ANALYSIS SUMMARY\n")
                    f.write("-" * 20 + "\n")
                    f.write(f"Risk Level: {summary.get('risk_level', 'Unknown')}\n")
                    f.write(f"Threats Detected: {'Yes' if summary.get('threats_detected') else 'No'}\n")
                    f.write(f"Confidence Score: {summary.get('confidence_score', 0):.1f}%\n")
                    if summary.get('data_sources_used'):
                        f.write(f"Data Sources: {', '.join(summary['data_sources_used'])}\n")
                    f.write("\n")
                
                # AI Analysis
                if data.get('ai_final_analysis'):
                    f.write("AI COMPREHENSIVE ANALYSIS\n")
                    f.write("-" * 30 + "\n")
                    f.write(f"{data['ai_final_analysis']}\n\n")
                
                # Data Sources
                sources = [
                    ('URLScan.io', 'urlscan_data'),
                    ('VirusTotal', 'virustotal_data'), 
                    ('AbuseIPDB', 'abuseipdb_data')
                ]
                
                for source_name, key in sources:
                    if key in data and data[key]:
                        f.write(f"{source_name.upper()} DATA\n")
                        f.write("-" * len(source_name) + "\n")
                        source_data = data[key]
                        if source_data.get('error'):
                            f.write(f"Error: {source_data['error']}\n")
                        else:
                            for field, value in source_data.items():
                                if value is not None:
                                    f.write(f"{field}: {value}\n")
                        f.write("\n")
            
            self.print_status(f"Text report saved to: {filename}", "SUCCESS")
        except Exception as e:
            self.print_status(f"Failed to save text report: {e}", "ERROR")

    def analyze_target(self, target: str, verbose: bool = False, output_format: str = None, output_file: str = None, no_ai: bool = False):
        """Analyze a single target"""
        self.print_status(f"Analyzing target: {target}", "LOADING")
        
        # Validate target
        try:
            validation_result = validate_target(target)
            if not validation_result['valid']:
                self.print_status(f"Invalid target: {validation_result['message']}", "ERROR")
                return False
            
            target_type = validation_result['type']
            if verbose:
                self.print_status(f"Target validated as: {target_type}", "SUCCESS")
        except Exception as e:
            self.print_status(f"Validation error: {e}", "ERROR")
            return False
        
        try:
            # Perform analysis
            if no_ai:
                # Disable AI analysis temporarily
                original_api_key = self.analyzer.ai_analyzer.api_key
                self.analyzer.ai_analyzer.api_key = None
                self.analyzer.ai_analyzer.client = None
                
                result = self.analyzer.analyze(target)
                
                # Restore original settings
                self.analyzer.ai_analyzer.api_key = original_api_key
                if original_api_key and original_api_key != 'your_openai_api_key_here':
                    try:
                        from openai import OpenAI
                        self.analyzer.ai_analyzer.client = OpenAI(api_key=original_api_key)
                    except ImportError:
                        pass
                        
                # Add info message about disabled AI
                if 'ai_error_message' not in result:
                    result['ai_error_message'] = "💡 AI analizi --no-ai parametresi ile devre dışı bırakıldı. Kural tabanlı analiz kullanılıyor..."
            else:
                result = self.analyzer.analyze(target)
            
            if result.get('error'):
                self.print_status(f"Analysis failed: {result['error']}", "ERROR")
                return False
            
            # Check if any APIs are working
            api_sources_working = self._check_api_sources(result)
            
            if not api_sources_working:
                print(f"\n{Fore.YELLOW}⚠️ Analysis completed with limited data!")
                print(f"{Fore.WHITE}Target: {self.format_target_info(target, target_type)}")
                self.print_status("All external APIs require configuration", "WARNING")
                print(f"{Fore.YELLOW}💡 Configure API keys in .env file for full analysis")
            else:
                print(f"\n{Fore.GREEN}✅ Analysis completed successfully!")
                print(f"{Fore.WHITE}Target: {self.format_target_info(target, target_type)}")
            
            # Display summary
            self.display_analysis_summary(result)
            
            if verbose:
                # Display detailed data sources
                self.display_data_sources(result)
                
                # Display AI analysis
                self.display_ai_analysis(result)
            
            # Save output if requested
            if output_file:
                if output_format == 'json':
                    self.save_json_report(result, output_file)
                elif output_format == 'txt':
                    self.save_text_report(result, output_file)
            
            return True
            
        except Exception as e:
            self.print_status(f"Analysis error: {e}", "ERROR")
            return False

    def analyze_batch(self, targets: List[str], verbose: bool = False, output_format: str = None, output_dir: str = None, no_ai: bool = False):
        """Analyze multiple targets"""
        self.print_status(f"Starting batch analysis of {len(targets)} targets", "INFO")
        
        if no_ai:
            self.print_status("AI analysis disabled for batch processing", "INFO")
        
        results = []
        successful = 0
        failed = 0
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Fore.CYAN}[{i}/{len(targets)}] {Fore.WHITE}Analyzing: {target}")
            
            try:
                # Apply no_ai setting for batch analysis
                if no_ai:
                    # Disable AI analysis temporarily
                    original_api_key = self.analyzer.ai_analyzer.api_key
                    self.analyzer.ai_analyzer.api_key = None
                    self.analyzer.ai_analyzer.client = None
                    
                    result = self.analyzer.analyze(target)
                    
                    # Restore original settings
                    self.analyzer.ai_analyzer.api_key = original_api_key
                    if original_api_key and original_api_key != 'your_openai_api_key_here':
                        try:
                            from openai import OpenAI
                            self.analyzer.ai_analyzer.client = OpenAI(api_key=original_api_key)
                        except ImportError:
                            pass
                else:
                    result = self.analyzer.analyze(target)
                    
                if result.get('error'):
                    self.print_status(f"Failed: {result['error']}", "ERROR")
                    failed += 1
                else:
                    # Check if any APIs are working
                    api_sources_working = self._check_api_sources(result)
                    
                    if not api_sources_working:
                        self.print_status("Limited analysis (API keys needed)", "WARNING")
                    else:
                        self.print_status("Completed successfully", "SUCCESS")
                    
                    successful += 1
                    
                    if verbose:
                        self.display_analysis_summary(result)
                
                results.append(result)
                
                # Save individual report if output directory specified
                if output_dir and not result.get('error'):
                    os.makedirs(output_dir, exist_ok=True)
                    filename = f"{output_dir}/report_{target.replace('://', '_').replace('/', '_').replace('.', '_')}"
                    
                    if output_format == 'json':
                        self.save_json_report(result, f"{filename}.json")
                    elif output_format == 'txt':
                        self.save_text_report(result, f"{filename}.txt")
                
            except Exception as e:
                self.print_status(f"Error: {e}", "ERROR")
                failed += 1
        
        # Summary
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}{Style.BRIGHT}BATCH ANALYSIS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}✅ Successful: {successful}")
        print(f"{Fore.RED}❌ Failed: {failed}")
        print(f"{Fore.WHITE}📊 Total: {len(targets)}")
        
        # Save combined report
        if output_dir and results:
            os.makedirs(output_dir, exist_ok=True)
            combined_report = {
                'batch_analysis': True,
                'timestamp': datetime.now().isoformat(),
                'total_targets': len(targets),
                'successful': successful,
                'failed': failed,
                'results': results
            }
            
            if output_format == 'json':
                self.save_json_report(combined_report, f"{output_dir}/batch_report.json")

    def show_cache_stats(self):
        """Show cache statistics"""
        try:
            stats = self.cache_manager.get_cache_stats()
            
            print(f"\n{Fore.CYAN}{'='*50}")
            print(f"{Fore.WHITE}{Style.BRIGHT}CACHE STATISTICS{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*50}")
            
            if 'error' in stats:
                self.print_status(f"Error getting cache stats: {stats['error']}", "ERROR")
                return
            
            print(f"{Fore.WHITE}Cache Directory: {Fore.YELLOW}{stats['cache_dir']}")
            print(f"{Fore.WHITE}Total Files: {Fore.GREEN}{stats['total_files']}")
            print(f"{Fore.WHITE}Total Size: {Fore.GREEN}{stats['total_size_bytes']:,} bytes")
            print(f"{Fore.WHITE}Expired Files: {Fore.RED}{stats['expired_files']}")
            print(f"{Fore.WHITE}TTL: {Fore.YELLOW}{stats['ttl_seconds']} seconds ({stats['ttl_seconds']//3600} hours)")
            
            if stats['expired_files'] > 0:
                print(f"\n{Fore.YELLOW}💡 Tip: Run --cache-clear to remove expired files")
                
        except Exception as e:
            self.print_status(f"Error showing cache stats: {str(e)}", "ERROR")

    def clear_cache(self):
        """Clear cache files"""
        try:
            print(f"\n{Fore.YELLOW}Clearing cache files...")
            cleared_count = self.cache_manager.clear_cache()
            
            if cleared_count > 0:
                self.print_status(f"Cleared {cleared_count} cache files", "SUCCESS")
            else:
                self.print_status("No cache files to clear", "INFO")
                
        except Exception as e:
            self.print_status(f"Error clearing cache: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(
        description="SecApp CLI - Advanced Cybersecurity Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s google.com                           # Analyze single domain
  %(prog)s https://example.com -v               # Verbose analysis of URL
  %(prog)s 8.8.8.8 -o json -f report.json      # Analyze IP and save JSON
  %(prog)s -b targets.txt -v -o txt -d reports/ # Batch analysis with reports
  %(prog)s --interactive                        # Interactive mode
        """
    )
    
    # Positional arguments
    parser.add_argument('target', nargs='?', help='Target to analyze (URL, domain, or IP)')
    
    # Optional arguments
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Show detailed analysis results')
    parser.add_argument('-b', '--batch', metavar='FILE',
                       help='File containing list of targets (one per line)')
    parser.add_argument('-o', '--output-format', choices=['json', 'txt'],
                       help='Output format for reports')
    parser.add_argument('-f', '--output-file', metavar='FILE',
                       help='Output file for single target analysis')
    parser.add_argument('-d', '--output-dir', metavar='DIR',
                       help='Output directory for batch analysis reports')
    parser.add_argument('--interactive', action='store_true',
                       help='Run in interactive mode')
    parser.add_argument('--no-ai', action='store_true',
                       help='Disable AI analysis and use rule-based analysis only')
    parser.add_argument('--cache-stats', action='store_true',
                       help='Show cache statistics')
    parser.add_argument('--cache-clear', action='store_true',
                       help='Clear all cached analysis results')
    parser.add_argument('--version', action='version', version='SecApp CLI 1.2.0')
    
    args = parser.parse_args()
    
    # Initialize CLI
    cli = SecAppCLI()
    
    # Handle cache commands first
    if args.cache_stats:
        cli.print_banner()
        cli.show_cache_stats()
        return
    
    if args.cache_clear:
        cli.print_banner()
        cli.clear_cache()
        return
    
    # Show banner
    cli.print_banner()
    
    # Interactive mode
    if args.interactive:
        cli.print_status("Starting interactive mode. Type 'help' for commands or 'quit' to exit.", "INFO")
        
        while True:
            try:
                user_input = input(f"\n{Fore.CYAN}SecApp> {Style.RESET_ALL}").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    cli.print_status("Goodbye!", "INFO")
                    break
                elif user_input.lower() == 'help':
                    print(f"""
{Fore.YELLOW}Available commands:
{Fore.WHITE}  <target>          - Analyze a target (URL, domain, or IP)
{Fore.WHITE}  help              - Show this help message  
{Fore.WHITE}  quit/exit/q       - Exit interactive mode
                    """)
                elif user_input:
                    cli.analyze_target(user_input, verbose=True, no_ai=args.no_ai)
                
            except KeyboardInterrupt:
                cli.print_status("\nGoodbye!", "INFO")
                break
            except EOFError:
                break
        
        return
    
    # Batch analysis
    if args.batch:
        if not os.path.exists(args.batch):
            cli.print_status(f"Batch file not found: {args.batch}", "ERROR")
            sys.exit(1)
        
        try:
            with open(args.batch, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if not targets:
                cli.print_status("No valid targets found in batch file", "ERROR")
                sys.exit(1)
            
            cli.analyze_batch(targets, args.verbose, args.output_format, args.output_dir, args.no_ai)
            
        except Exception as e:
            cli.print_status(f"Error reading batch file: {e}", "ERROR")
            sys.exit(1)
        
        return
    
    # Single target analysis
    if args.target:
        success = cli.analyze_target(args.target, args.verbose, args.output_format, args.output_file, args.no_ai)
        sys.exit(0 if success else 1)
    
    # No arguments provided
    parser.print_help()
    sys.exit(1)

if __name__ == '__main__':
    main()
