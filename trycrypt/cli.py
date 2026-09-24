import typer
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .vault import CryptomatorVault
from .analysis.metadata import analyze_metadata
from .analysis.password import analyze_password_resilience
from .analysis.hygiene import analyze_hygiene

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

    report = {"metadata": None, "password": None, "hygiene": None}

    console.print("\n[bold]» [1/3] Analyzing metadata leakage...[/bold]")
    meta = analyze_metadata(v)
    report["metadata"] = meta
    if "error" not in meta:
        _render_metadata(meta)

    console.print("\n[bold]» [2/3] Analyzing password resilience...[/bold]")
    pw = analyze_password_resilience(v)
    report["password"] = pw
    if "error" not in pw:
        _render_password(pw)

    console.print("\n[bold]» [3/3] Analyzing OS hygiene...[/bold]")
    hyg = analyze_hygiene(v)
    report["hygiene"] = hyg
    _render_hygiene(hyg)

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


@app.command()
def hygiene(
    vault: Path = typer.Argument(..., help="Path to Cryptomator vault directory"),
):
    """Run only the OS hygiene module."""
    v = CryptomatorVault(vault)
    if not v.validate():
        console.print("[bold red]✗ Invalid Cryptomator vault[/bold red]")
        raise typer.Exit(1)
    console.print(Panel.fit(
        "[bold yellow]🛡️  OS Hygiene Check[/bold yellow]",
        border_style="yellow",
    ))
    result = analyze_hygiene(v)
    _render_hygiene(result)


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
    console.print(f"[bold]Verdict:[/bold] {r['entropy']['interpretation']}\n")

    fp = Table(title="File-Size Fingerprints", border_style="magenta")
    fp.add_column("Inferred type")
    fp.add_column("Count", justify="right")
    for name, count in r["fingerprints"].items():
        fp.add_row(name, f"{count:,}")
    console.print(fp)


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

    gpu_t = Table(title="GPU Time-to-Crack (RockYou, 14.3M)", border_style="red")
    gpu_t.add_column("GPU", style="bold")
    gpu_t.add_column("Hashes/sec", justify="right")
    gpu_t.add_column("Time to crack", justify="right")
    for gpu_name, info in r["gpu_estimates"].items():
        gpu_t.add_row(gpu_name, f"{info['hashes_per_second']:,.2f}", info["time_to_crack_human"])
    console.print(gpu_t)
    console.print(f"[bold]Verdict:[/bold] {r['verdict']}")


def _render_hygiene(r: dict):
    score_table = Table(title="OS Hygiene Score", border_style="yellow")
    score_table.add_column("Metric", style="bold")
    score_table.add_column("Value", justify="right")
    score_table.add_row("Score (0-100)", str(r["score"]))
    score_table.add_row("Verdict", r["verdict"])
    console.print(score_table)

    if r["permissions"]:
        p = r["permissions"]
        perms = Table(title="Masterkey Permissions", border_style="cyan")
        perms.add_column("Field", style="bold")
        perms.add_column("Value", justify="right")
        perms.add_row("Mode", p["mode_human"])
        perms.add_row("Octal", p["mode_octal"])
        perms.add_row("World readable", str(p["world_readable"]))
        perms.add_row("World writable", str(p["world_writable"]))
        perms.add_row("Severity", p["severity"])
        perms.add_row("Finding", p["finding"])
        console.print(perms)

    if r["symlinks"]:
        sym = Table(title="Symlinks", border_style="red")
        sym.add_column("Path")
        sym.add_column("Escapes vault")
        sym.add_column("Severity")
        for s in r["symlinks"]:
            sym.add_row(s["path"], str(s["escapes_vault"]), s["severity"])
        console.print(sym)

    if r["cloud_sync"]:
        cs = Table(title="Cloud Sync Detection", border_style="magenta")
        cs.add_column("Provider")
        cs.add_column("Severity")
        cs.add_column("Finding")
        for c in r["cloud_sync"]:
            cs.add_row(c["provider"], c["severity"], c["finding"])
        console.print(cs)

    if r["path_traversal"]:
        pt = Table(title="Path Traversal Risks", border_style="red")
        pt.add_column("Path")
        pt.add_column("Severity")
        pt.add_column("Finding")
        for p in r["path_traversal"]:
            pt.add_row(p["path"], p["severity"], p["finding"])
        console.print(pt)


if __name__ == "__main__":
    app()
