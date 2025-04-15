import argparse
import sys
from urllib.parse import urlparse
from rich.console import Console

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(description="Web Directory Search Tool with Recursive Scanning")
    parser.add_argument("-u", "--url", type=str, help="Comma-separated list of target URLs (e.g., http://example.com,http://test.com)")
    parser.add_argument("-d", "--domain", type=str, help="Comma-separated list of target domains (e.g., example.com,test.com)")
    parser.add_argument("-w", "--wordlist", type=str, required=False, help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=40, help="Number of concurrent threads")
    parser.add_argument("-x", "--extensions", type=str, default="", help="File extensions to check (e.g., php,txt,html)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive scanning of directories and subdomains")
    parser.add_argument("--depth", type=int, default=1, help="Maximum depth for recursive scanning (default: 1)")
    parser.add_argument("-o", "--output", type=str, help="Output file to save results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--proxy", type=str, help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--rate-limit", type=float, default=0, help="Limit requests per second (0 for no limit)")
    parser.add_argument("--status-filter", type=str, help="Comma-separated list of status codes to include (e.g., 200,301,302)")
    parser.add_argument("--export-format", type=str, default="csv", choices=["csv", "json", "html"], help="Format to export results (csv, json, html)")
    parser.add_argument("--method", type=str, default="GET", choices=["GET", "POST", "PUT", "DELETE"], help="HTTP method to use (default: GET)")
    parser.add_argument("--headers", type=str, help="Custom headers in JSON format (e.g., '{\"Authorization\": \"Bearer token\"}')")
    parser.add_argument("--payload", type=str, help="Payload for POST/PUT requests")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--disable-wildcard", action="store_true", help="Disable wildcard detection")
    parser.add_argument("--user-agent", type=str, help="Custom User-Agent string (e.g., 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')")
    args = parser.parse_args()

    if args.url:
        urls = args.url.split(",")
        for url in urls:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                console.print(f"[red]Error: Invalid URL format: {url}[/red]")
                sys.exit(1)
    elif not args.url and not args.domain:
        console.print("[red]Error: You must provide at least one URL or domain to scan.[/red]")
        sys.exit(1)

    return args