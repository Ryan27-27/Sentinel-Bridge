#!/usr/bin/env python3
"""
AppSec Pipeline Sentinel - Automated Application Security Monitoring & Reporting Platform
Author: Aryan Adityaa
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.table import Table

console = Console()
# Separate stderr console so --fail-on gate messages never land inside
# stdout when --output json is piped straight to a file (e.g. in CI).
err_console = Console(stderr=True)

BANNER = """
[bold cyan]
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗ 
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
[/bold cyan]
[bold white]       AppSec Pipeline Sentinel  [/bold white][dim]v1.0.0 | by Aryan Adityaa[/dim]
[dim]  Automated SSDLC Security Monitoring, Triage & Reporting Platform[/dim]
"""

@click.group()
def cli():
    """AppSec Pipeline Sentinel - SSDLC Security Automation Platform"""
    pass

@cli.command()
def banner():
    """Show the Sentinel banner"""
    console.print(BANNER)

@cli.command()
@click.argument('target', default='.')
@click.option('--type', 'scan_type', default='all', type=click.Choice(['sast','dast','secrets','all']), help='Scan type')
@click.option('--severity', default='all', type=click.Choice(['critical','high','medium','low','all']), help='Minimum severity filter')
@click.option('--output', default='terminal', type=click.Choice(['terminal','json','csv']), help='Output format')
@click.option('--save', is_flag=True, help='Save results to DB')
@click.option('--target-url', default=None, help='Live URL for DAST scanning (default: auto-launches bundled demo target on :5050)')
@click.option('--exclude', multiple=True, help='Directory name(s) to exclude from SAST/secrets scanning (repeatable, e.g. --exclude test_fixtures)')
@click.option('--fail-on', default=None, type=click.Choice(['critical', 'high', 'medium', 'low']),
              help='Exit with a non-zero status if any finding at or above this severity is present (for CI/CD build gating)')
def scan(target, scan_type, severity, output, save, target_url, exclude, fail_on):
    """Run security scans (SAST/DAST/Secrets) on a target"""
    from scanner.engine import ScanEngine
    engine = ScanEngine(console)
    findings = engine.run(target, scan_type, severity, output, save, target_url=target_url, exclude_dirs=list(exclude))

    if fail_on:
        sev_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        threshold = sev_rank[fail_on]
        gating = [f for f in findings if sev_rank.get(f['severity'], 99) <= threshold]
        if gating:
            err_console.print(
                f"\n[bold red]✗ Build gate failed:[/bold red] {len(gating)} finding(s) at or above "
                f"'{fail_on}' severity."
            )
            sys.exit(1)
        err_console.print(f"\n[bold green]✓ Build gate passed:[/bold green] no findings at or above '{fail_on}' severity.")

@cli.command()
@click.option('--limit', default=20, help='Number of vulnerabilities to show')
@click.option('--severity', default='all', type=click.Choice(['critical','high','medium','low','all']))
@click.option('--status', default='all', type=click.Choice(['open','fixed','wontfix','all']))
@click.option('--sort', default='severity', type=click.Choice(['severity','date','mttr']))
def vulns(limit, severity, status, sort):
    """List and triage vulnerabilities from the database"""
    from aggregator.triage import TriageEngine
    engine = TriageEngine(console)
    engine.list_vulns(limit, severity, status, sort)

@cli.command()
@click.argument('vuln_id')
@click.argument('action', type=click.Choice(['assign','close','wontfix','reopen']))
@click.option('--assignee', default=None, help='Assign to team/person')
@click.option('--note', default=None, help='Add a note')
def triage(vuln_id, action, assignee, note):
    """Triage a specific vulnerability (assign/close/wontfix/reopen)"""
    from aggregator.triage import TriageEngine
    engine = TriageEngine(console)
    engine.triage_vuln(vuln_id, action, assignee, note)

@cli.command()
@click.option('--type', 'report_type', default='summary', type=click.Choice(['summary','mttr','trend','pipeline','full']))
@click.option('--days', default=30, help='Lookback period in days')
@click.option('--format', 'fmt', default='terminal', type=click.Choice(['terminal','csv','html']))
def dashboard(report_type, days, fmt):
    """View AppSec metrics dashboard and reports"""
    from dashboard.metrics import MetricsDashboard
    dash = MetricsDashboard(console)
    dash.render(report_type, days, fmt)

@cli.command()
@click.argument('target_url')
@click.option('--wordlist', default=None, help='Path to custom wordlist (default: bundled common.txt)')
def discover(target_url, wordlist):
    """Discover live routes/endpoints on a target using ffuf (falls back to built-in scanner if ffuf isn't installed)"""
    from scanner.discovery import discover_routes, ffuf_available, WORDLIST_PATH
    from rich.table import Table
    from rich import box

    wl = wordlist or WORDLIST_PATH
    engine_label = "[green]ffuf[/green]" if ffuf_available() else "[yellow]built-in fallback (ffuf not installed)[/yellow]"
    console.print(Panel(f"Discovering routes on [bold]{target_url}[/bold] using {engine_label}\nWordlist: [dim]{wl}[/dim]", border_style="cyan"))

    results = discover_routes(target_url, wordlist=wl)

    if not results:
        console.print("[dim]No routes discovered (target may be unreachable or wordlist didn't match anything).[/dim]")
        return

    table = Table(box=box.ROUNDED, border_style="green", title=f"[bold]{len(results)} routes discovered[/bold]")
    table.add_column("Path", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Length", justify="right")
    table.add_column("Tool", style="dim")

    status_color = {200: "green", 201: "green", 204: "green", 301: "cyan", 302: "cyan", 401: "yellow", 403: "red"}
    for r in sorted(results, key=lambda x: x['status']):
        c = status_color.get(r['status'], 'white')
        table.add_row(r['path'], f"[{c}]{r['status']}[/{c}]", str(r['length']), r['tool'])

    console.print(table)

@cli.command()
@click.option('--dry-run', is_flag=True, help='Preview automation without making changes')
def automate(dry_run):
    """Run automation: dedup, auto-assign, SLA breach alerts"""
    from automation.pipeline import AutomationPipeline
    pipeline = AutomationPipeline(console)
    pipeline.run(dry_run)

@cli.command()
def status():
    """Show system status: DB, scanner, pipeline health"""
    from scanner.engine import ScanEngine
    from aggregator.db import Database
    db = Database()
    
    console.print(BANNER)
    
    table = Table(box=box.ROUNDED, border_style="cyan", show_header=True, header_style="bold cyan")
    table.add_column("Component", style="bold white", min_width=25)
    table.add_column("Status", min_width=12)
    table.add_column("Details", style="dim")

    stats = db.get_stats()
    
    table.add_row("Database (SQLite)", "[bold green]● ONLINE[/bold green]", f"{stats['total']} vulns stored")
    table.add_row("SAST Engine (Semgrep-sim)", "[bold green]● READY[/bold green]", "Pattern-based code analysis")
    table.add_row("DAST Engine (live HTTP scan)", "[bold green]● READY[/bold green]", "Real requests against running targets")
    import shutil as _shutil
    ffuf_status = "[bold green]● DETECTED[/bold green]" if _shutil.which('ffuf') else "[yellow]● FALLBACK MODE[/yellow]"
    ffuf_detail = "Using real ffuf for route discovery" if _shutil.which('ffuf') else "ffuf not installed — using built-in scanner"
    table.add_row("Route Discovery (ffuf)", ffuf_status, ffuf_detail)
    table.add_row("Secrets Scanner", "[bold green]● READY[/bold green]", "Regex + entropy detection")
    table.add_row("Automation Pipeline", "[bold green]● ACTIVE[/bold green]", "Dedup + triage + SLA alerts")
    table.add_row("Metrics Dashboard", "[bold green]● READY[/bold green]", "MTTR, trend, severity charts")
    table.add_row("CI/CD Integration", "[bold cyan]● CONFIGURED[/bold cyan]", ".github/workflows/sentinel.yml")
    table.add_row("Docker / K8s", "[bold cyan]● READY[/bold cyan]", "Dockerfile + k8s manifests")
    
    console.print(table)
    console.print()
    
    stat_table = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
    stat_table.add_column("Metric", style="dim")
    stat_table.add_column("Value", style="bold")
    stat_table.add_row("Critical", f"[bold red]{stats['critical']}[/bold red]")
    stat_table.add_row("High",     f"[bold orange3]{stats['high']}[/bold orange3]")
    stat_table.add_row("Medium",   f"[bold yellow]{stats['medium']}[/bold yellow]")
    stat_table.add_row("Low",      f"[bold green]{stats['low']}[/bold green]")
    stat_table.add_row("Fixed",    f"[bold cyan]{stats['fixed']}[/bold cyan]")
    
    console.print(Panel(stat_table, title="[bold]Vulnerability Stats[/bold]", border_style="cyan", padding=(0,1)))

@cli.command()
def demo():
    """Run a full demo: scan → triage → dashboard → automate"""
    import time
    from scanner.engine import ScanEngine
    from aggregator.triage import TriageEngine
    from dashboard.metrics import MetricsDashboard
    from automation.pipeline import AutomationPipeline

    console.print(BANNER)
    console.print(Panel("[bold cyan]Running Full Demo Pipeline[/bold cyan]\nScan → Triage → Dashboard → Automate", border_style="cyan"))
    console.print()
    time.sleep(0.5)

    console.rule("[bold cyan]Step 1: Security Scan[/bold cyan]")
    ScanEngine(console).run('scanner/test_fixtures', 'all', 'all', 'terminal', True)
    console.print()
    time.sleep(0.3)

    console.rule("[bold cyan]Step 2: Vulnerability Triage[/bold cyan]")
    TriageEngine(console).list_vulns(10, 'all', 'all', 'severity')
    console.print()
    time.sleep(0.3)

    console.rule("[bold cyan]Step 3: Metrics Dashboard[/bold cyan]")
    MetricsDashboard(console).render('full', 30, 'terminal')
    console.print()
    time.sleep(0.3)

    console.rule("[bold cyan]Step 4: Automation Pipeline[/bold cyan]")
    AutomationPipeline(console).run(dry_run=False)
    console.print()

    console.print(Panel(
        "[bold green]✓ Demo complete![/bold green]\n\n"
        "All components operational:\n"
        "  [cyan]•[/cyan] SAST/DAST/Secrets scans executed\n"
        "  [cyan]•[/cyan] Vulnerabilities triaged and stored\n"
        "  [cyan]•[/cyan] Metrics dashboard rendered\n"
        "  [cyan]•[/cyan] Automation pipeline ran (dedup + assign + SLA)\n\n"
        "[dim]Run [bold]sentinel status[/bold] to see live stats[/dim]",
        border_style="green", title="[bold green]Pipeline Complete[/bold green]"
    ))

if __name__ == '__main__':
    cli()
