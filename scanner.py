import concurrent.futures
import dns.resolver
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress
from http_utils import check_url, normalize_url

console = Console()

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

def handle_target(target, mode, progress, task_id, wordlist, session, args, wildcard_content):
    if mode == "url":
        results = scan_directories(
            target, wordlist, args.extensions.split(","), args.threads, args.recursive, session, args.verbose,
            rate_limit=args.rate_limit, status_filter=args.status_filter, progress=progress, task_id=task_id,
            max_depth=args.depth, method=args.method, payload=args.payload, headers=args.headers, wildcard_content=wildcard_content
        )
        return results, "dir"
    elif mode == "domain":
        results = scan_subdomains(
            target, wordlist, args.threads, args.recursive, args.verbose, progress=progress, task_id=task_id
        )
        return results, "dns"

def process_targets(urls, domains, wordlist, session, args, wildcard_content):
    with Progress(console=console) as progress:
        tasks = {target: progress.add_task(f"[cyan]Scanning {target}[/cyan]", total=len(wordlist)) for target in urls + domains}
        results = []
        for target in urls + domains:
            mode = "url" if target in urls else "domain"
            task_id = tasks[target]
            target_results, mode = handle_target(target, mode, progress, task_id, wordlist, session, args, wildcard_content)
            results.append((target_results, target, mode))
            progress.update(task_id, completed=len(wordlist))
        return results