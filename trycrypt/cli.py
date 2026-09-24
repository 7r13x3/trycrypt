import typer
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .vault import CryptomatorVault
from .analysis.metadata import analyze_metadata

app = typer.Typer(
    name="trycrypt",
    help="Offline security auditor for Cryptomator vaults",
    no_args_is_help=True,
)
console = Console()


@app.command()
def audit(
    vault: Path = typer.Argument(..., help="Path to Cryptomator vault directory"),
    output: str = typer.Option("table", "--output", "-o", help="table | json"),
    export: Path = typer.Option(None, "--export", "-e", help="Export report to file"),
):
    """Run a full security audit on a Cryptomator vault."""
    console.print(Panel.fit(
        "[bold cyan]🔐 trycrypt — Vault Auditor[/bold cyan]\n"
        f"[dim]Target: {vault}[/dim]",
        border_style="cyan",
    ))

    v = CryptomatorVault(vault)
    if not v.validate():
        console.print("[bold red]✗ Invalid Cryptomator vault[/bold red]")
        raise typer.Exit(1)

    console.print("[green]✓ Valid Cryptomator vault detected[/green]")

    try:
        mk = v.parse_masterkey()
        console.print(f"[dim]  • Masterkey version: {mk.version}[/dim]")
        if mk.scrypt_params:
            console.print(f"[dim]  • scrypt N (cost):  {mk.scrypt_params.cost_param}[/dim]")
            console.print(f"[dim]  • scrypt r (block): {mk.scrypt_params.block_size}[/dim]")
    except Exception as e:
        console.print(f"[yellow]⚠ Could not parse masterkey: {e}[/yellow]")

    console.print("\n[bold]» Analyzing metadata leakage...[/bold]")
    result = analyze_metadata(v)

    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        raise typer.Exit(1)

    if output == "json":
        console.print_json(json.dumps(result, indent=2, default=str))
    else:
        _render_tables(result)

    if export:
        export.write_text(json.dumps(result, indent=2, default=str))
        console.print(f"\n[green]✓ Report exported to {export}[/green]")


def _render_tables(r: dict):
    t = Table(title="Metadata Leakage Analysis", border_style="cyan")
    t.add_column("Metric", style="bold")
    t.add_column("Value", justify="right")
    t.add_row("Total encrypted files", f"{r['total_files']:,}")
    t.add_row("Total encrypted bytes", f"{r['total_bytes']:,}")
    t.add_row("Shannon entropy H(X)", f"{r['entropy']['shannon']:.4f}")
    t.add_row("Max entropy H_max", f"{r['entropy']['max']:.4f}")
    t.add_row("Normalized entropy", f"{r['entropy']['normalized']:.4f}")
    console.print(t)
    console.print(f"\n[bold]Verdict:[/bold] {r['entropy']['interpretation']}\n")

    fp = Table(title="File-Size Fingerprints", border_style="magenta")
    fp.add_column("Inferred type")
    fp.add_column("Count", justify="right")
    for name, count in r["fingerprints"].items():
        fp.add_row(name, f"{count:,}")
    console.print(fp)

    tm = Table(title="Temporal Activity (Top Hours)", border_style="yellow")
    tm.add_column("Hour of day")
    tm.add_column("File writes", justify="right")
    for row in r["temporal_top_hours"]:
        tm.add_row(f"{row['hour']:02d}:00", f"{row['count']:,}")
    console.print(tm)


if __name__ == "__main__":
    app()
