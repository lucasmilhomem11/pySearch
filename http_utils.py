import requests
from urllib.parse import urljoin
import time
from rich.console import Console

console = Console()

def normalize_url(url):
    return url.rstrip(".")

def setup_session(args):
    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent or "pySearch/1.0"})
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})
        console.print(f"[cyan]Using proxy: {args.proxy}[/cyan]")
    return session

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
                time.sleep(1 / rate_limit)
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