import os, sys
from datetime import datetime
from rich.table import Table
from rich.panel import Panel
from rich import box

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from aggregator.db import Database

# Location-prefix -> owning team routing table (mirrors CODEOWNERS-style automation)
ROUTING_RULES = [
    (("src/auth", "middleware/auth", "login"), "backend-team"),
    (("src/api",), "backend-team"),
    (("frontend", "src/components", ".js", ".ts", ".jsx", ".tsx"), "frontend-team"),
    (("config", "k8s", "Dockerfile", "deploy"), "devops-team"),
    (("package.json", "requirements.txt"), "platform-team"),
]

SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 90}


class AutomationPipeline:
    def __init__(self, console):
        self.console = console
        self.db = Database()

    def _route(self, location):
        loc = (location or '').lower()
        for keywords, team in ROUTING_RULES:
            if any(k.lower() in loc for k in keywords):
                return team
        return "security-team"

    def run(self, dry_run=False):
        vulns = self.db.get_vulns(status='all', limit=1000)

        # 1. Deduplication — group by normalized title
        seen_titles = {}
        duplicates = []
        for v in vulns:
            key = (v['title'].lower().strip(), v['location'])
            if key in seen_titles:
                duplicates.append(v)
            else:
                seen_titles[key] = v['id']

        # 2. Auto-assignment for unassigned open vulns
        to_assign = [v for v in vulns if v['status'] == 'open' and not v['assigned_to']]
        assignments = []
        for v in to_assign:
            team = self._route(v['location'])
            assignments.append((v['id'], v['title'], team))
            if not dry_run:
                self.db.update_vuln(v['id'], assigned_to=team)

        # 3. SLA breach detection
        now = datetime.now()
        breaches = []
        for v in vulns:
            if v['status'] != 'open':
                continue
            try:
                discovered = datetime.fromisoformat(v['discovered_at'])
                age_days = (now - discovered).days
                sla = SLA_DAYS.get(v['severity'], 30)
                if age_days > sla:
                    breaches.append((v['id'], v['title'], v['severity'], age_days, sla))
            except Exception:
                continue

        self._render(duplicates, assignments, breaches, dry_run)

    def _render(self, duplicates, assignments, breaches, dry_run):
        mode = "[yellow](DRY RUN — no changes written)[/yellow]" if dry_run else "[green](changes applied)[/green]"
        self.console.print(Panel(f"[bold cyan]Automation Pipeline Run[/bold cyan] {mode}", border_style="cyan"))

        # Dedup report
        if duplicates:
            t = Table(box=box.SIMPLE, title=f"[bold]Deduplication — {len(duplicates)} duplicate(s) found[/bold]", border_style="dim")
            t.add_column("ID", style="dim")
            t.add_column("Title", max_width=50)
            for v in duplicates[:10]:
                t.add_row(v['id'], v['title'])
            self.console.print(t)
        else:
            self.console.print("[dim]No duplicate findings detected.[/dim]")

        # Auto-assignment report
        if assignments:
            t = Table(box=box.ROUNDED, title=f"[bold]Auto-Assignment — {len(assignments)} vuln(s) routed[/bold]", border_style="green")
            t.add_column("ID", style="cyan")
            t.add_column("Title", max_width=40)
            t.add_column("Routed To", style="bold green")
            for vid, title, team in assignments:
                t.add_row(vid, title, team)
            self.console.print(t)
        else:
            self.console.print("[dim]No unassigned open vulnerabilities to route.[/dim]")

        # SLA breach report
        if breaches:
            t = Table(box=box.ROUNDED, title=f"[bold red]SLA Breach Alerts — {len(breaches)} overdue[/bold red]", border_style="red")
            t.add_column("ID", style="cyan")
            t.add_column("Title", max_width=35)
            t.add_column("Severity")
            t.add_column("Age (days)", justify="right")
            t.add_column("SLA (days)", justify="right", style="dim")
            sev_color = {"critical": "bold red", "high": "bold orange3", "medium": "bold yellow", "low": "bold green"}
            for vid, title, sev, age, sla in breaches:
                c = sev_color.get(sev, 'white')
                t.add_row(vid, title, f"[{c}]{sev.upper()}[/{c}]", str(age), str(sla))
            self.console.print(t)
            self.console.print(Panel(
                f"[bold red]⚠ {len(breaches)} vulnerabilities have breached SLA[/bold red]\n"
                "[dim]In production this triggers a Slack alert via webhook + auto-creates a JIRA escalation ticket.[/dim]",
                border_style="red"
            ))
        else:
            self.console.print(Panel("[bold green]✓ No SLA breaches — all open vulnerabilities within remediation targets[/bold green]", border_style="green"))
