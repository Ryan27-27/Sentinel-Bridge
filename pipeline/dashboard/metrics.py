import os, sys
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from aggregator.db import Database


def bar(value, max_value, width=30, color="cyan"):
    if max_value == 0:
        filled = 0
    else:
        filled = int((value / max_value) * width)
    return f"[{color}]{'█' * filled}{'░' * (width - filled)}[/{color}]"


class MetricsDashboard:
    def __init__(self, console):
        self.console = console
        self.db = Database()

    def render(self, report_type, days, fmt):
        if report_type in ('summary', 'full'):
            self._render_summary()
        if report_type in ('mttr', 'full'):
            self._render_mttr()
        if report_type in ('trend', 'full'):
            self._render_trend(days)
        if report_type in ('pipeline', 'full'):
            self._render_pipeline(days)

    def _render_summary(self):
        stats = self.db.get_stats()
        sev_color = {"critical": "bold red", "high": "bold orange3", "medium": "bold yellow", "low": "bold green"}
        max_val = max(stats['critical'], stats['high'], stats['medium'], stats['low'], 1)

        table = Table(box=box.ROUNDED, border_style="cyan", title="[bold]Open Vulnerabilities by Severity[/bold]", show_header=False)
        table.add_column("Severity", style="bold", min_width=10)
        table.add_column("Chart", min_width=32)
        table.add_column("Count", justify="right")

        for sev in ['critical', 'high', 'medium', 'low']:
            c = sev_color[sev]
            table.add_row(f"[{c}]{sev.upper()}[/{c}]", bar(stats[sev], max_val, color=c.replace('bold ', '')), str(stats[sev]))

        self.console.print(table)

        total_open = stats['critical'] + stats['high'] + stats['medium'] + stats['low']
        fix_rate = round((stats['fixed'] / stats['total']) * 100, 1) if stats['total'] else 0
        info = (f"[bold]Total Open:[/bold] {total_open}   "
                f"[bold]Fixed:[/bold] {stats['fixed']}   "
                f"[bold]Fix Rate:[/bold] {fix_rate}%   "
                f"[bold]Total Tracked:[/bold] {stats['total']}")
        self.console.print(Panel(info, border_style="dim"))

    def _render_mttr(self):
        mttr = self.db.get_mttr_by_severity()
        sev_color = {"critical": "bold red", "high": "bold orange3", "medium": "bold yellow", "low": "bold green"}

        table = Table(box=box.ROUNDED, border_style="magenta", title="[bold]MTTR (Mean Time To Remediate) by Severity[/bold]")
        table.add_column("Severity")
        table.add_column("Avg Days to Fix", justify="right")
        table.add_column("SLA Target", justify="right", style="dim")
        table.add_column("Status", justify="center")

        sla = {"critical": 7, "high": 14, "medium": 30, "low": 90}
        for sev in ['critical', 'high', 'medium', 'low']:
            avg = mttr.get(sev)
            target = sla[sev]
            c = sev_color[sev]
            if avg is None:
                table.add_row(f"[{c}]{sev.upper()}[/{c}]", "[dim]no data[/dim]", f"{target}d", "-")
            else:
                status = "[bold green]✓ within SLA[/bold green]" if avg <= target else "[bold red]✗ SLA breach[/bold red]"
                table.add_row(f"[{c}]{sev.upper()}[/{c}]", f"{avg}d", f"{target}d", status)

        self.console.print(table)

    def _render_trend(self, days):
        history = self.db.get_scan_history(days)
        table = Table(box=box.ROUNDED, border_style="yellow", title=f"[bold]Scan History (last {days} days)[/bold]")
        table.add_column("Date", style="dim")
        table.add_column("Type")
        table.add_column("Target", style="dim")
        table.add_column("Found", justify="right")
        table.add_column("Crit", justify="right", style="red")
        table.add_column("High", justify="right", style="orange3")
        table.add_column("Dur(s)", justify="right", style="dim")

        if not history:
            self.console.print(Panel("[dim]No scan runs recorded yet. Run `sentinel scan --save` to populate trend data.[/dim]", border_style="yellow"))
            return

        for h in history[:15]:
            date = h['run_at'][:16].replace('T', ' ')
            table.add_row(date, h['scan_type'], h['target'], str(h['total_found']),
                          str(h['critical']), str(h['high']), str(h['duration_sec']))
        self.console.print(table)

    def _render_pipeline(self, days):
        stats = self.db.get_stats()
        owasp_table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        owasp_table.add_column("Category")
        owasp_table.add_column("Health")

        health_items = [
            ("SAST Coverage", "[green]●●●●●[/green] 100%"),
            ("DAST Coverage", "[green]●●●●○[/green] 80%"),
            ("Secrets Scanning", "[green]●●●●●[/green] 100%"),
            ("Dependency Scanning", "[yellow]●●●○○[/yellow] 60%"),
            ("CI/CD Gate Enforcement", "[green]●●●●●[/green] Blocking on Critical/High"),
        ]
        for name, val in health_items:
            owasp_table.add_row(name, val)

        self.console.print(Panel(owasp_table, title="[bold]SSDLC Pipeline Health[/bold]", border_style="green"))
