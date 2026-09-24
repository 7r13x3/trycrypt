import typer
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .vault import CryptomatorVault
from .analysis.metadata import analyze_metadata
from .analysis.password import analyze_password_resilience

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

    report = {"metadata": None, "password": None}

    console.print("\n[bold]» Analyzing metadata leakage...[/bold]")
    meta = analyze_metadata(v)
    report["metadata"] = meta
    if "error" not in meta:
        _render_metadata(meta)

    console.print("\n[bold]» Analyzing password resilience...[/bold]")
    pw = analyze_password_resilience(v)
    report["password"] = pw
    if "error" not in pw:
        _render_password(pw)

    if output == "json":
        console.print_json(json.dumps(report, indent=2, default=str))

    if export:
        export.write_text(json.dumps(report, indent=2, default=str))
        console.print(f"\n[green]✓ Report exported to {export}[/green]")


@app.command()
def crack(
    vault: Path = typer.Argument(..., help="Path to Cryptomator vault directory"),
    gpu: str = typer.Option("RTX 4090", "--gpu", help="GPU profile for estimation"),
):
    """Estimate password cracking time for a Cryptomator vault."""
    v = CryptomatorVault(vault)
    if not v.validate():
        console.print("[bold red]✗ Invalid Cryptomator vault[/bold red]")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold magenta]💥 Password Resilience — {gpu}[/bold magenta]",
        border_style="magenta",
    ))
    result = analyze_password_resilience(v, gpu_profile=gpu)
    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        raise typer.Exit(1)
    _render_password(result)


def _render_metadata(r: dict):
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


def _render_password(r: dict):
    kdf = Table(title="Key Derivation Function (KDF)", border_style="cyan")
    kdf.add_column("Parameter", style="bold")
    kdf.add_column("Value", justify="right")
    kdf.add_row("Algorithm", r["kdf"]["algorithm"])
    kdf.add_row("N (cost)", f"{r['kdf']['N']:,}")
    kdf.add_row("r (block size)", str(r["kdf"]["r"]))
    kdf.add_row("p (parallelism)", str(r["kdf"]["p"]))
    kdf.add_row("Memory required", f"{r['kdf']['memory_mb']:.2f} MB per hash")
    console.print(kdf)

    if "cpu_benchmark" in r:
        cpu = Table(title="CPU Benchmark", border_style="yellow")
        cpu.add_column("Metric", style="bold")
        cpu.add_column("Value", justify="right")
        cpu.add_row("Seconds per hash", f"{r['cpu_benchmark']['seconds_per_hash']}")
        cpu.add_row("Hashes per second", f"{r['cpu_benchmark']['hashes_per_second']:,}")
        cpu.add_row("Time to crack (RockYou)", r["cpu_benchmark"]["time_to_crack_human"])
        console.print(cpu)

    gpu_t = Table(title="GPU Time-to-Crack Estimates (RockYou, 14.3M passwords)", border_style="red")
    gpu_t.add_column("GPU", style="bold")
    gpu_t.add_column("Hashes/sec", justify="right")
    gpu_t.add_column("Time to crack", justify="right")
    for gpu_name, info in r["gpu_estimates"].items():
        gpu_t.add_row(
            gpu_name,
            f"{info['hashes_per_second']:,.2f}",
            info["time_to_crack_human"],
        )
    console.print(gpu_t)

    console.print(f"\n[bold]Verdict:[/bold] {r['verdict']}")
    console.print(f"[dim]Target GPU: {r['target_gpu']}[/dim]")


if __name__ == "__main__":
    app()
