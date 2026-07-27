#!/usr/bin/env python3
"""
Fast CORS Misconfiguration Scanner
A high-performance tool to detect CORS vulnerabilities
"""

import argparse
import asyncio
import aiohttp
import sys
import json
import csv
import re
from urllib.parse import urlparse
from datetime import datetime
from typing import List, Dict, Optional, Set
import ssl
import certifi
import os
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

# Custom color scheme for severity levels
SEVERITY_COLORS = {
    'CRITICAL': Fore.RED + Style.BRIGHT,
    'HIGH': Fore.RED,
    'MEDIUM': Fore.BLUE + Style.BRIGHT,
    'LOW': Fore.CYAN,
    'INFO': Fore.WHITE
}

SEVERITY_BG = {
    'CRITICAL': Back.RED + Fore.WHITE + Style.BRIGHT,
    'HIGH': Back.RED + Fore.WHITE,
    'MEDIUM': Back.BLUE + Fore.WHITE + Style.BRIGHT,
    'LOW': Back.CYAN + Fore.BLACK,
    'INFO': Back.WHITE + Fore.BLACK
}

class CORSScanner:
    def __init__(self, concurrency=50, timeout=10, verify_ssl=False, output_format='console', quiet=False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.output_format = output_format
        self.quiet = quiet
        self.results = []
        self.total_scanned = 0
        self.vulnerable_count = 0
        self.vulnerable_urls = []
        
        # CORS test origins
        self.test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            "https://evil.com;https://legitimate.com",
            "https://sub.legitimate.com",
            "http://localhost",
            "http://127.0.0.1",
            "file://",
        ]
        
        # Headers to check
        self.cors_headers = [
            'access-control-allow-origin',
            'access-control-allow-credentials',
            'access-control-allow-methods',
            'access-control-allow-headers',
        ]

    def print_banner(self, url_count):
        """Print beautiful banner"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print(f"   🔍 CORS Misconfiguration Scanner")
        print(f"{'='*70}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Targets:{Style.RESET_ALL} {Fore.GREEN}{url_count}{Style.RESET_ALL} URLs")
        print(f"  {Fore.WHITE}Concurrency:{Style.RESET_ALL} {Fore.GREEN}{self.concurrency}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Timeout:{Style.RESET_ALL} {Fore.GREEN}{self.timeout}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    async def scan_url(self, session: aiohttp.ClientSession, url: str) -> Dict:
        """Scan a single URL for CORS misconfigurations"""
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'issues': [],
            'cors_headers_found': {},  # Store found CORS headers
            'details': {}
        }
        
        try:
            # First, make a normal request to get baseline
            async with session.get(url, ssl=self.verify_ssl) as response:
                baseline_headers = dict(response.headers)
                # Store all CORS-related headers
                for header_name, header_value in baseline_headers.items():
                    if header_name.lower() in self.cors_headers:
                        result['cors_headers_found'][header_name] = header_value
                
                result['details']['baseline'] = {
                    'status': response.status,
                    'headers': {k.lower(): v for k, v in baseline_headers.items() 
                               if k.lower() in self.cors_headers}
                }
            
            # Test with different origins
            for origin in self.test_origins:
                try:
                    headers = {'Origin': origin}
                    async with session.options(url, headers=headers, ssl=self.verify_ssl) as response:
                        cors_result = self.analyze_cors_response(response, origin)
                        if cors_result:
                            # Store the vulnerable headers
                            cors_result['vulnerable_headers'] = {
                                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin', 'Not Present'),
                                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials', 'Not Present'),
                                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', 'Not Present'),
                                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers', 'Not Present')
                            }
                            result['issues'].append(cors_result)
                            result['vulnerable'] = True
                            
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
                
                # Also test with GET requests
                try:
                    headers = {'Origin': origin}
                    async with session.get(url, headers=headers, ssl=self.verify_ssl) as response:
                        cors_result = self.analyze_cors_response(response, origin)
                        if cors_result and cors_result not in result['issues']:
                            # Store the vulnerable headers
                            cors_result['vulnerable_headers'] = {
                                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin', 'Not Present'),
                                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials', 'Not Present'),
                                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', 'Not Present'),
                                'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers', 'Not Present')
                            }
                            result['issues'].append(cors_result)
                            result['vulnerable'] = True
                            
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
            
            # Check for ACAO wildcard with credentials
            if self.check_wildcard_credentials(result):
                result['vulnerable'] = True
                
        except asyncio.TimeoutError:
            result['details']['error'] = 'Timeout'
        except aiohttp.ClientError as e:
            result['details']['error'] = str(e)
        except Exception as e:
            result['details']['error'] = str(e)
        
        self.total_scanned += 1
        if result['vulnerable']:
            self.vulnerable_count += 1
            self.vulnerable_urls.append(result)
            if not self.quiet:
                self.print_vulnerability(result)
        elif not self.quiet:
            print(f"{Fore.GREEN}[SAFE]{Style.RESET_ALL} {url}")
        
        return result
    
    def analyze_cors_response(self, response, origin: str) -> Optional[Dict]:
        """Analyze CORS response for vulnerabilities"""
        acao_header = response.headers.get('Access-Control-Allow-Origin', '').strip()
        acac_header = response.headers.get('Access-Control-Allow-Credentials', '').strip().lower()
        
        issue = {
            'origin': origin,
            'method': response.method,
            'status': response.status,
            'acao_header': acao_header,
            'acac_header': acac_header,
            'vulnerability': None
        }
        
        # Check for reflected origin
        if acao_header == origin and origin != 'null':
            issue['vulnerability'] = 'Reflected Origin'
            issue['severity'] = 'HIGH'
            issue['description'] = 'Server reflects any Origin header without validation'
            
        # Check for null origin allowed
        elif acao_header == 'null' and origin == 'null':
            issue['vulnerability'] = 'Null Origin Allowed'
            issue['severity'] = 'MEDIUM'
            issue['description'] = 'Server allows null origin, enabling sandboxed iframe attacks'
            
        # Check for wildcard with credentials
        elif acao_header == '*' and acac_header == 'true':
            issue['vulnerability'] = 'Wildcard ACAO with Credentials'
            issue['severity'] = 'CRITICAL'
            issue['description'] = 'Wildcard origin with credentials allows any site to make authenticated requests'
            
        # Check for wildcard without credentials
        elif acao_header == '*':
            issue['vulnerability'] = 'Wildcard ACAO (non-sensitive endpoints)'
            issue['severity'] = 'LOW'
            issue['description'] = 'Wildcard origin without credentials on non-sensitive endpoints'
            
        # Check for insecure protocols
        elif origin.startswith('http://') and acao_header:
            issue['vulnerability'] = 'Allows HTTP origins'
            issue['severity'] = 'MEDIUM'
            issue['description'] = 'Server accepts insecure HTTP origins'
            
        # Check for prefix/suffix bypass
        elif self.check_prefix_bypass(acao_header, origin):
            issue['vulnerability'] = 'Potential prefix/suffix bypass'
            issue['severity'] = 'HIGH'
            issue['description'] = 'Domain validation can be bypassed with prefix/suffix manipulation'
            
        if issue['vulnerability']:
            return issue
        return None
    
    def check_prefix_bypass(self, acao_header: str, origin: str) -> bool:
        """Check for prefix or suffix domain bypass"""
        if acao_header.startswith('*.') or acao_header.endswith('.*'):
            return True
        if origin.endswith(acao_header) or acao_header.endswith(origin.split('://')[-1]):
            return True
        return False
    
    def check_wildcard_credentials(self, result: Dict) -> bool:
        """Check for wildcard with credentials vulnerability"""
        for issue in result['issues']:
            if issue.get('vulnerability') == 'Wildcard ACAO with Credentials':
                return True
        return False
    
    def get_severity_icon(self, severity):
        """Get icon for severity level"""
        icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🔵',
            'LOW': '💠',
            'INFO': '⚪'
        }
        return icons.get(severity, '⚪')
    
    def print_vulnerability(self, result: Dict):
        """Print vulnerability findings with beautiful formatting"""
        url = result['url']
        issues = result['issues']
        
        # Print URL with VULNERABLE badge
        print(f"\n{Back.RED}{Fore.WHITE}{Style.BRIGHT} VULNERABLE {Style.RESET_ALL} {Fore.WHITE}{Style.BRIGHT}{url}{Style.RESET_ALL}")
        
        # Print separator
        print(f"{Fore.RED}{'─'*70}{Style.RESET_ALL}")
        
        # Print CORS headers found
        if result.get('cors_headers_found'):
            print(f"  {Fore.CYAN}{Style.BRIGHT}CORS Headers Present:{Style.RESET_ALL}")
            for header, value in result['cors_headers_found'].items():
                print(f"    {Fore.WHITE}• {header}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
            print()
        
        # Print each issue
        for idx, issue in enumerate(issues, 1):
            severity = issue.get('severity', 'INFO')
            vulnerability = issue.get('vulnerability', 'Unknown')
            description = issue.get('description', '')
            origin = issue['origin']
            
            # Get color for severity
            color = SEVERITY_COLORS.get(severity, Fore.WHITE)
            bg_color = SEVERITY_BG.get(severity, Back.WHITE)
            icon = self.get_severity_icon(severity)
            
            # Print severity badge
            print(f"  {bg_color} {icon} {severity} {Style.RESET_ALL} {color}{vulnerability}{Style.RESET_ALL}")
            
            # Print description
            if description:
                print(f"  {Fore.WHITE}└─ {description}{Style.RESET_ALL}")
            
            # Print vulnerable headers for this issue
            if 'vulnerable_headers' in issue:
                print(f"  {Fore.YELLOW}{Style.BRIGHT}  📋 Vulnerable Headers:{Style.RESET_ALL}")
                for header, value in issue['vulnerable_headers'].items():
                    if value != 'Not Present':
                        # Highlight the vulnerable header values
                        if header == 'Access-Control-Allow-Origin' and value in ['*', 'null', origin]:
                            print(f"    {Fore.RED}⚠ {header}: {value} {Style.RESET_ALL}{Fore.RED}(VULNERABLE){Style.RESET_ALL}")
                        elif header == 'Access-Control-Allow-Credentials' and value.lower() == 'true':
                            print(f"    {Fore.RED}⚠ {header}: {value} {Style.RESET_ALL}{Fore.RED}(VULNERABLE){Style.RESET_ALL}")
                        else:
                            print(f"    {Fore.WHITE}  {header}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
            
            print(f"  {Fore.WHITE}  • Test Origin:{Style.RESET_ALL} {Fore.YELLOW}{origin}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}  • Method:{Style.RESET_ALL} {issue['method']} | {Fore.WHITE}Status:{Style.RESET_ALL} {issue['status']}")
            
            # Add spacing between issues
            if idx < len(issues):
                print()
        
        # Print separator
        print(f"{Fore.RED}{'─'*70}{Style.RESET_ALL}\n")
    
    async def scan_bulk(self, urls: List[str]):
        """Scan multiple URLs concurrently"""
        # Configure SSL context
        ssl_context = ssl.create_default_context(cafile=certifi.where()) if self.verify_ssl else False
        
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            limit_per_host=10,
            ssl=ssl_context if self.verify_ssl else False
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
        ) as session:
            tasks = [self.scan_url(session, url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            self.results = [r for r in results if isinstance(r, dict)]
        
        return self.results
    
    def print_vulnerable_urls_list(self):
        """Print final list of all vulnerable URLs with their vulnerable CORS headers"""
        if not self.vulnerable_urls:
            print(f"\n{Fore.GREEN}{Style.BRIGHT}{'='*70}")
            print(f"   ✅ NO VULNERABILITIES FOUND")
            print(f"{'='*70}{Style.RESET_ALL}\n")
            return
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print(f"   🎯 VULNERABLE URLs WITH CORS HEADERS")
        print(f"{'='*70}{Style.RESET_ALL}\n")
        
        for idx, result in enumerate(self.vulnerable_urls, 1):
            url = result['url']
            issues = result['issues']
            
            # Count severity levels
            severities = [issue.get('severity', 'INFO') for issue in issues]
            has_critical = 'CRITICAL' in severities
            has_high = 'HIGH' in severities
            
            # Determine URL color based on highest severity
            if has_critical:
                url_color = Back.RED + Fore.WHITE + Style.BRIGHT
                badge = f"{Fore.RED}🔴 CRITICAL{Style.RESET_ALL}"
            elif has_high:
                url_color = Back.RED + Fore.WHITE
                badge = f"{Fore.RED}🟠 HIGH{Style.RESET_ALL}"
            else:
                url_color = Fore.YELLOW + Style.BRIGHT
                badge = f"{Fore.YELLOW}🔵 MEDIUM/LOW{Style.RESET_ALL}"
            
            # Print URL
            print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}{Style.BRIGHT}#{idx}{Style.RESET_ALL}  {url_color} {url} {Style.RESET_ALL} {badge}")
            print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}")
            
            # Show CORS headers present
            if result.get('cors_headers_found'):
                print(f"  {Fore.CYAN}📋 CORS Headers Found:{Style.RESET_ALL}")
                for header, value in result['cors_headers_found'].items():
                    print(f"    {Fore.WHITE}• {header}:{Style.RESET_ALL} {Fore.GREEN}{value}{Style.RESET_ALL}")
                print()
            
            # Show vulnerable headers for each issue
            print(f"  {Fore.RED}🚨 Vulnerabilities Detected:{Style.RESET_ALL}")
            for issue_idx, issue in enumerate(issues, 1):
                severity = issue.get('severity', 'INFO')
                vulnerability = issue.get('vulnerability', 'Unknown')
                color = SEVERITY_COLORS.get(severity, Fore.WHITE)
                icon = self.get_severity_icon(severity)
                origin = issue['origin']
                
                print(f"    {color}{issue_idx}. {icon} [{severity}] {vulnerability}{Style.RESET_ALL}")
                print(f"       {Fore.WHITE}Test Origin:{Style.RESET_ALL} {Fore.YELLOW}{origin}{Style.RESET_ALL}")
                
                # Show vulnerable headers
                if 'vulnerable_headers' in issue:
                    print(f"       {Fore.RED}Vulnerable Headers:{Style.RESET_ALL}")
                    for header, value in issue['vulnerable_headers'].items():
                        if value != 'Not Present':
                            # Mark vulnerable headers in red
                            is_vulnerable = False
                            if header == 'Access-Control-Allow-Origin':
                                if value in ['*', 'null', origin]:
                                    is_vulnerable = True
                            elif header == 'Access-Control-Allow-Credentials':
                                if value.lower() == 'true':
                                    is_vulnerable = True
                            
                            if is_vulnerable:
                                print(f"         {Fore.RED}⚠ {header}: {value}{Style.RESET_ALL}")
                            else:
                                print(f"         {Fore.WHITE}{header}: {value}{Style.RESET_ALL}")
                print()
            
            print()
        
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"  {Fore.RED}{Style.BRIGHT}Total Vulnerable URLs: {len(self.vulnerable_urls)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def print_summary(self):
        """Print beautiful scan summary"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'='*70}")
        print(f"   📊 SCAN SUMMARY")
        print(f"{'='*70}{Style.RESET_ALL}")
        
        print(f"  {Fore.WHITE}Total URLs scanned:{Style.RESET_ALL} {Fore.GREEN}{self.total_scanned}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Vulnerable URLs:{Style.RESET_ALL} {Fore.RED}{Style.BRIGHT}{self.vulnerable_count}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Safe URLs:{Style.RESET_ALL} {Fore.GREEN}{self.total_scanned - self.vulnerable_count}{Style.RESET_ALL}")
        
        # Calculate statistics
        if self.total_scanned > 0:
            percentage = (self.vulnerable_count / self.total_scanned) * 100
            
            # Color code the percentage
            if percentage > 50:
                percent_color = Fore.RED + Style.BRIGHT
            elif percentage > 25:
                percent_color = Fore.YELLOW
            else:
                percent_color = Fore.GREEN
                
            print(f"  {Fore.WHITE}Vulnerability Rate:{Style.RESET_ALL} {percent_color}{percentage:.1f}%{Style.RESET_ALL}")
        
        # Count by severity
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_issues = 0
        for result in self.results:
            if result['vulnerable']:
                for issue in result['issues']:
                    severity = issue.get('severity', 'INFO')
                    if severity in severity_count:
                        severity_count[severity] += 1
                        total_issues += 1
        
        if total_issues > 0:
            print(f"\n  {Fore.WHITE}{Style.BRIGHT}Findings by Severity:{Style.RESET_ALL}")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = severity_count[severity]
                if count > 0:
                    color = SEVERITY_COLORS.get(severity, Fore.WHITE)
                    icon = self.get_severity_icon(severity)
                    bar = '█' * min(count, 50)
                    print(f"    {color}{icon} {severity}:{Style.RESET_ALL} {Fore.WHITE}{count}{Style.RESET_ALL} {color}{bar}{Style.RESET_ALL}")
        
        print(f"\n  {Fore.WHITE}Scan completed at:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def generate_report(self, output_file: Optional[str] = None):
        """Generate scan report"""
        if not self.quiet:
            # Always show vulnerable URLs list with CORS headers
            self.print_vulnerable_urls_list()
        
        if self.output_format == 'json':
            self.export_json(output_file)
        elif self.output_format == 'csv':
            self.export_csv(output_file)
        else:
            self.print_summary()
    
    def export_json(self, output_file: Optional[str] = None):
        """Export results to JSON"""
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_scanned': self.total_scanned,
                'vulnerable_count': self.vulnerable_count,
                'concurrency': self.concurrency,
                'timeout': self.timeout
            },
            'vulnerable_urls': [
                {
                    'url': r['url'],
                    'cors_headers': r.get('cors_headers_found', {}),
                    'issues': r['issues']
                }
                for r in self.results if r['vulnerable']
            ],
            'results': self.results
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n{Fore.GREEN}[✓] Report saved to: {output_file}{Style.RESET_ALL}")
        else:
            print(json.dumps(report, indent=2))
    
    def export_csv(self, output_file: Optional[str] = None):
        """Export results to CSV"""
        if not output_file:
            output_file = f"cors_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Vulnerable', 'CORS Headers Present', 'Vulnerability', 'Severity', 
                           'Test Origin', 'ACAO', 'ACAC', 'ACAM', 'ACAH'])
            
            for result in self.results:
                cors_headers_str = ', '.join([f"{k}: {v}" for k, v in result.get('cors_headers_found', {}).items()])
                
                if result['vulnerable']:
                    for issue in result['issues']:
                        vuln_headers = issue.get('vulnerable_headers', {})
                        writer.writerow([
                            result['url'],
                            'Yes',
                            cors_headers_str,
                            issue.get('vulnerability', ''),
                            issue.get('severity', ''),
                            issue.get('origin', ''),
                            vuln_headers.get('Access-Control-Allow-Origin', ''),
                            vuln_headers.get('Access-Control-Allow-Credentials', ''),
                            vuln_headers.get('Access-Control-Allow-Methods', ''),
                            vuln_headers.get('Access-Control-Allow-Headers', '')
                        ])
                else:
                    writer.writerow([result['url'], 'No', cors_headers_str, '', '', '', '', '', '', ''])
        
        print(f"\n{Fore.GREEN}[✓] CSV report saved to: {output_file}{Style.RESET_ALL}")

def read_urls_from_file(filename: str) -> List[str]:
    """Read URLs from file"""
    urls = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Add protocol if missing
                if not line.startswith(('http://', 'https://')):
                    line = 'https://' + line
                urls.append(line)
    return urls

def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

async def main():
    parser = argparse.ArgumentParser(
        description='🔍 Fast CORS Misconfiguration Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan single URL
  python3 scanner.py -u https://example.com
  
  # Scan multiple URLs from file
  python3 scanner.py -f urls.txt
  
  # Scan with custom concurrency and timeout
  python3 scanner.py -f urls.txt -c 100 -t 5
  
  # Export results to JSON
  python3 scanner.py -f urls.txt -o results.json -of json
  
  # Export results to CSV
  python3 scanner.py -f urls.txt -o results.csv -of csv
        '''
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-u', '--url', help='Single URL to scan')
    input_group.add_argument('-f', '--file', help='File containing URLs (one per line)')
    input_group.add_argument('-stdin', action='store_true', help='Read URLs from stdin')
    
    # Configuration options
    parser.add_argument('-c', '--concurrency', type=int, default=50,
                       help='Number of concurrent requests (default: 50)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-of', '--output-format', choices=['json', 'csv', 'console'],
                       default='console', help='Output format (default: console)')
    parser.add_argument('--verify-ssl', action='store_true',
                       help='Verify SSL certificates')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress real-time output, show only final results')
    
    args = parser.parse_args()
    
    # Get URLs
    urls = []
    if args.url:
        if validate_url(args.url):
            urls.append(args.url)
        else:
            print(f"{Fore.RED}[!] Invalid URL: {args.url}{Style.RESET_ALL}")
            sys.exit(1)
    elif args.file:
        urls = read_urls_from_file(args.file)
        if not urls:
            print(f"{Fore.RED}[!] No valid URLs found in file{Style.RESET_ALL}")
            sys.exit(1)
    elif args.stdin:
        urls = [line.strip() for line in sys.stdin if line.strip()]
    
    # Initialize scanner
    scanner = CORSScanner(
        concurrency=args.concurrency,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        output_format=args.output_format,
        quiet=args.quiet
    )
    
    # Print banner
    if not args.quiet:
        scanner.print_banner(len(urls))
    
    # Run scan
    start_time = datetime.now()
    await scanner.scan_bulk(urls)
    end_time = datetime.now()
    
    # Generate report
    if not args.quiet:
        duration = (end_time - start_time).total_seconds()
        print(f"{Fore.CYAN}[✓] Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
    
    # Generate final report with vulnerable URLs and their CORS headers
    scanner.generate_report(args.output)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
