#!/usr/bin/env python3
import time
import sys
from rich.console import Console
from arg_parser import parse_args
from wordlist import read_wordlist
from http_utils import setup_session, normalize_url
from scanner import process_targets
from ui import print_ascii_art
from output import display_and_save_results  # Import the display function

console = Console()

def main():
    start_time = time.time()
    
    print_ascii_art(console)
    
    args = parse_args()
    wordlist = read_wordlist(args.wordlist)
    session = setup_session(args)
    
    console.print(f"[cyan]Using User-Agent: [/cyan] [bold cyan]{session.headers['User-Agent']}[/bold cyan]")
    
    urls = args.url.split(",") if args.url else []
    domains = args.domain.split(",") if args.domain else []
    
    if len(urls) > 3 or len(domains) > 3:
        console.print("[red]Error: You can only scan up to 3 targets at the same time.[/red]")
        sys.exit(1)
    
    wildcard_content = None
    results = process_targets(urls, domains, wordlist, session, args, wildcard_content)
    
    # Iterate over results and display tables
    for target_results, target, mode in results:
        display_and_save_results(target_results, target, args, mode)
    
    elapsed_time = time.time() - start_time
    console.print(f"[green]Execution completed in {elapsed_time:.2f} seconds.[/green]")

if __name__ == "__main__":
    main()