import os, sys
from datetime import datetime
from rich.table import Table
from rich.panel import Panel
from rich import box

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from aggregator.db import Database


class TriageEngine:
    def __init__(self, console):
        self.console = console
        self.db = Database()

    def list_vulns(self, limit, severity, status, sort):
        vulns = self.db.get_vulns(severity=severity, status=status, limit=limit, sort=sort)

        if not vulns:
            self.console.print(Panel("[yellow]No vulnerabilities match these filters.[/yellow]", border_style="yellow"))
            return

        sev_color = {"critical": "bold red", "high": "bold orange3", "medium": "bold yellow", "low": "bold green"}
        status_color = {"open": "red", "fixed": "green", "wontfix": "dim", "closed": "dim"}

        table = Table(box=box.ROUNDED, border_style="cyan", title=f"[bold]Vulnerabilities ({len(vulns)} shown, sorted by {sort})[/bold]")
        table.add_column("ID", style="bold cyan")
        table.add_column("Severity", justify="center")
        table.add_column("Title", max_width=40)
        table.add_column("Location", style="dim", max_width=28)
        table.add_column("Status", justify="center")
        table.add_column("Assigned", style="dim")

        for v in vulns:
            sc = sev_color.get(v['severity'], 'white')
            stc = status_color.get(v['status'], 'white')
            loc = v['location'] or '-'
            if v.get('line_number'):
                loc += f":{v['line_number']}"
            table.add_row(
                v['id'],
                f"[{sc}]{v['severity'].upper()}[/{sc}]",
                v['title'],
                loc,
                f"[{stc}]{v['status']}[/{stc}]",
                v['assigned_to'] or '[dim]unassigned[/dim]'
            )
        self.console.print(table)

    def triage_vuln(self, vuln_id, action, assignee, note):
        vuln = self.db.get_vuln(vuln_id)
        if not vuln:
            self.console.print(Panel(f"[bold red]✗ Vulnerability {vuln_id} not found[/bold red]", border_style="red"))
            return

        updates = {}
        if action == 'assign':
            if not assignee:
                self.console.print("[red]✗ --assignee is required for 'assign' action[/red]")
                return
            updates['assigned_to'] = assignee
            updates['status'] = 'open'
            msg = f"[green]✓[/green] {vuln_id} assigned to [bold]{assignee}[/bold]"
        elif action == 'close':
            updates['status'] = 'fixed'
            updates['fixed_at'] = datetime.now().isoformat()
            msg = f"[green]✓[/green] {vuln_id} marked as [bold green]fixed[/bold green]"
        elif action == 'wontfix':
            updates['status'] = 'wontfix'
            msg = f"[yellow]✓[/yellow] {vuln_id} marked as [bold yellow]wontfix[/bold yellow]"
        elif action == 'reopen':
            updates['status'] = 'open'
            updates['fixed_at'] = None
            msg = f"[cyan]✓[/cyan] {vuln_id} reopened"
        else:
            self.console.print(f"[red]Unknown action: {action}[/red]")
            return

        if note:
            existing = vuln.get('notes') or ''
            updates['notes'] = (existing + f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}").strip()

        self.db.update_vuln(vuln_id, **updates)
        self.console.print(Panel(msg, border_style="cyan", title=vuln['title'][:60]))
