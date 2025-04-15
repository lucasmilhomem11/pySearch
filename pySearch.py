#!/usr/bin/env python3

import argparse
import concurrent.futures
import requests
from urllib.parse import urljoin, urlparse
import dns.resolver
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import sys
import time
import pyfiglet
from rich.text import Text
import json
from rich.markdown import Markdown

console = Console()

ascii_art = pyfiglet.figlet_format("pySearch")

def gradient_text(ascii_art, start_color=(255, 0, 0), end_color=(0, 0, 255)):
    gradient = Text()
    lines = ascii_art.splitlines()
    total_lines = len(lines)
    for i, line in enumerate(lines):
        ratio = i / total_lines
        r, g, b = [int(start + (end - start) * ratio) for start, end in zip(start_color, end_color)]
        gradient.append(line + "\n", style=f"rgb({r},{g},{b})")
    return gradient

colored_ascii = gradient_text(ascii_art, start_color=(255, 0, 0), end_color=(0, 0, 255))

console.print(colored_ascii)


# support for custom headers and payloads in the argument parser
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

def read_wordlist(wordlist_path=None):
    default_wordlist = ["admin", "login", "dashboard", "config", "index", "home", "about", "contact", "api", "assets", "docs", "temp"]
    if not wordlist_path:
        console.print("[yellow]No wordlist provided. Using default wordlist.[/yellow]")
        return default_wordlist

    console.print(f"[cyan]Using wordlist:[/cyan] [bold cyan]{wordlist_path}[/bold cyan]")
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            wordlist = [line.strip() for line in f if line.strip()]
            console.print(f"[cyan]Wordlist contains {len(wordlist)} words.[/cyan]")
            return wordlist
    except FileNotFoundError:
        console.print("[red]Error: Wordlist file not found.[/red]")
        sys.exit(1)

normalize_url = lambda url: url.rstrip(".")

def check_url(url, extensions, session, verbose, rate_limit=0, status_filter=None, method="GET", payload=None, headers=None, wildcard_content=None):
    results = set()  
    try:
        if status_filter:
            allowed_statuses = {int(code) for code in status_filter.split(",")}
        else:
            allowed_statuses = None

        url = normalize_url(url)

        headers = headers or {}

        res = session.request(method, url, data=payload, headers=headers, allow_redirects=False, timeout=8)
        if verbose:
            console.print(f"[cyan]Checking URL: {url} - Status: {res.status_code}[/cyan]")
        content_length = res.headers.get("Content-Length", len(res.content)) 

        if wildcard_content and res.content == wildcard_content:
            if verbose:
                console.print(f"[yellow]Skipping wildcard response for {url}[/yellow]")
            return list(results)

        if (allowed_statuses and res.status_code in allowed_statuses) or (res.status_code != 404 and not allowed_statuses):
            results.add((url, res.status_code, content_length))
        
        for ext in extensions:
            if rate_limit > 0:
                time.sleep(1 / rate_limit)  # Enforce rate limit
            ext_url = normalize_url(f"{url}.{ext}")
            res = session.request(method, ext_url, data=payload, headers=headers, allow_redirects=False, timeout=5)
            if verbose:
                console.print(f"[cyan]Checking URL: {ext_url} - Status: {res.status_code}[/cyan]")
            content_length = res.headers.get("Content-Length", len(res.content))  

            if wildcard_content and res.content == wildcard_content:
                if verbose:
                    console.print(f"[yellow]Skipping wildcard response for {ext_url}[/yellow]")
                continue

            if (allowed_statuses and res.status_code in allowed_statuses) or (res.status_code != 404 and not allowed_statuses):
                results.add((ext_url, res.status_code, content_length))
    except requests.RequestException as e:
        if verbose:
            console.print(f"[yellow]Warning: Failed to check {url}: {e}[/yellow]")
    return list(results)  

def wildcard_response(base_url, session, method="GET"):
    test_url = urljoin(base_url, "nonexistent")
    try:
        res = session.request(method, test_url, timeout=5)
        return res.content if res.status_code == 200 else None
    except requests.RequestException:
        return None

def check_subdomain(subdomain, domain, verbose):
    full_domain = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(full_domain, "A")
        if verbose:
            console.print(f"[cyan]Found Subdomain: {full_domain} - IPs: {[str(r) for r in answers]}[/cyan]")
        return (full_domain, [str(r) for r in answers])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return None
    except Exception as e:
        if verbose:
            console.print(f"[yellow]Warning: Failed to check {full_domain}: {e}[/yellow]")
        return None

def scan_directories(url, wordlist, extensions, threads, recursive, session, verbose, rate_limit=0, depth=0, max_depth=1, status_filter=None, progress=None, task_id=None, method="GET", payload=None, headers=None, wildcard_content=None):
    if depth > max_depth:
        return []

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_word = {
            executor.submit(check_url, urljoin(url, word), extensions, session, verbose, rate_limit, status_filter, method, payload, headers, wildcard_content): word
            for word in wordlist
        }
        for future in concurrent.futures.as_completed(future_to_word):
            word = future_to_word[future]
            result = future.result()
            for url, status, length in result:
                results.append((url, status, length, word))  
            if progress and task_id:
                progress.advance(task_id)

    results = list({normalize_url(url): (url, status, length, word) for url, status, length, word in results}.values())

    if recursive:
        for found_url, status, _, word in results:
            if found_url.endswith("/") and status in {200, 301, 302}:
                sub_results = scan_directories(
                    found_url, wordlist, extensions, threads, recursive, session, verbose, rate_limit, depth + 1, max_depth, status_filter, progress, task_id, method, payload, headers, wildcard_content
                )
                results.extend(sub_results)

    return results

def scan_subdomains(domain, wordlist, threads, recursive, verbose, progress=None, task_id=None):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain, subdomain, domain, verbose): subdomain
            for subdomain in wordlist
        }
        for future in concurrent.futures.as_completed(future_to_subdomain):
            result = future.result()
            if result:
                results.append(result)
            if progress and task_id:
                progress.advance(task_id)  
    
    if recursive:
        for subdomain, _ in results:
            console.print(f"[green]Recursing into subdomain {subdomain}[/green]")
            sub_results = scan_subdomains(subdomain, wordlist, threads, False, verbose, progress, task_id)
            results.extend(sub_results)
    
    if progress and task_id and not results:
        progress.advance(task_id, advance=len(wordlist))
    
    return results

def display_and_save_results(results, target, args, mode="dir"):
    table = Table(title=f"{mode.upper()} Enumeration Results", show_header=True, header_style="bold magenta")
    if mode == "dir":
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Content Length", style="yellow")
        table.add_column("Directory", style="magenta")  # 3rd column
        for url, status, length, word in results:
            table.add_row(url, str(status), str(length), word)
    else:
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP Addresses", style="green")
        for subdomain, ips in results:
            table.add_row(subdomain, ", ".join(ips))
    console.print(table)

    if args.output:
        save_results(results, f"{args.output}_{target.replace('://', '_').replace('/', '_')}", mode, args.export_format)

def save_results(results, output_file, mode="dir", export_format="csv"):
    if not output_file:
        return

    if export_format == "csv":
        headers = ["URL", "Status", "Content-Length", "Directory"] if mode == "dir" else ["Subdomain", "IP Addresses"]
        rows = [",".join(map(str, row)) for row in results]
    elif export_format == "json":
        headers, rows = None, json.dumps(results, indent=4)
    elif export_format == "html":
        headers = ["URL", "Status", "Content Length", "Directory"] if mode == "dir" else ["Subdomain", "IP Addresses"]
        rows = "".join(f"<tr>{''.join(f'<td>{col}</td>' for col in row)}</tr>" for row in results)
        rows = f"<table><tr>{''.join(f'<th>{header}</th>' for header in headers)}</tr>{rows}</table>"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join([",".join(headers)] + rows) if headers else rows)

    console.print(f"[blue]Results saved to {output_file} in {export_format.upper()} format[/blue]")
def main():
    start_time = time.time()

    args = parse_args()
    wordlist = read_wordlist(args.wordlist)
    session = requests.Session()

    session.headers.update({"User-Agent": args.user_agent or "pySearch/1.0"})
    console.print(f"[cyan]Using User-Agent: [/cyan] [bold cyan]{session.headers['User-Agent']}[/bold cyan]")

    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})
        console.print(f"[cyan]Using proxy: {args.proxy}[/cyan]")

    urls = args.url.split(",") if args.url else []
    domains = args.domain.split(",") if args.domain else []

    if len(urls) > 3 or len(domains) > 3:
        console.print("[red]Error: You can only scan up to 3 targets at the same time.[/red]")
        sys.exit(1)

    process_targets(urls, domains, wordlist, session, args, None)

    elapsed_time = time.time() - start_time
    console.print(f"[green]Execution completed in {elapsed_time:.2f} seconds.[/green]")

def handle_target(target, mode, progress, task_id, wordlist, session, args, wildcard_content):
    if mode == "url":
        results = scan_directories(
            target, wordlist, args.extensions.split(","), args.threads, args.recursive, session, args.verbose,
            rate_limit=args.rate_limit, status_filter=args.status_filter, progress=progress, task_id=task_id,
            max_depth=args.depth, method=args.method, payload=args.payload, headers=args.headers, wildcard_content=wildcard_content
        )
        display_and_save_results(results, target, args, mode="dir")
    elif mode == "domain":
        results = scan_subdomains(
            target, wordlist, args.threads, args.recursive, args.verbose, progress=progress, task_id=task_id
        )
        display_and_save_results(results, target, args, mode="dns")

def process_targets(urls, domains, wordlist, session, args, wildcard_content):
    with Progress(console=console) as progress:
        tasks = {target: progress.add_task(f"[cyan]Scanning {target}[/cyan]", total=len(wordlist)) for target in urls + domains}

        for target in urls + domains:
            mode = "url" if target in urls else "domain"
            task_id = tasks[target]
            handle_target(target, mode, progress, task_id, wordlist, session, args, wildcard_content)
            progress.update(task_id, completed=len(wordlist))  # Combine progress update here

if __name__ == "__main__":
    main()