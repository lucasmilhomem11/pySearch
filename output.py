import json
from rich.console import Console
from rich.table import Table

console = Console()

def display_and_save_results(results, target, args, mode="dir"):
    table = Table(title=f"{mode.upper()} Enumeration Results", show_header=True, header_style="bold magenta")
    if mode == "dir":
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Content Length", style="yellow")
        table.add_column("Directory", style="magenta")
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