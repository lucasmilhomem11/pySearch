from rich.console import Console

console = Console()

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