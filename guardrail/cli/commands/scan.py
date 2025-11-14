"""
Scan command - Run security tests against AI agents
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from ...core.scanner import SecurityScanner

console = Console()


def scan(
    prompt: str = typer.Argument(
        "You are a helpful assistant.",
        help="Agent's system prompt to test"
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Show minimal output"
    )
):
    """
    Run security scan on an AI agent

    Example:
        guardrail scan "You are a helpful customer service assistant."
    """
    if not quiet:
        console.print()
        console.print(Panel(
            "[bold cyan]GuardRail Security Scanner[/bold cyan]",
            box=box.DOUBLE,
            border_style="cyan"
        ))
        console.print()
        console.print(f"[dim]Testing agent with prompt:[/dim]")
        console.print(f"[yellow]'{prompt[:60]}...'[/yellow]\n")

    scanner = SecurityScanner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Running security tests...", total=None)
        results = scanner.scan(prompt)
        progress.update(task, completed=True)

    console.print()
    _display_results(results, quiet)


def _display_results(results: dict, quiet: bool):
    """Display scan results"""

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column(style="cyan bold")
    table.add_column(style="white")

    table.add_row("Tests Run:", str(results["total_tests"]))
    table.add_row("Vulnerable:", f"[red]{results['vulnerable']}[/red]")
    table.add_row("Safe:", f"[green]{results['safe']}[/green]")
    table.add_row("Security Score:", f"[yellow]{results['security_score']}[/yellow]")

    console.print(table)
    console.print()

    if results["vulnerable"] > 0:
        console.print(f"[red bold]{results['vulnerable']} vulnerabilities found[/red bold]\n")

        if not quiet:
            for i, finding in enumerate(results["findings"][:5], 1):
                severity_color = {
                    "critical": "red",
                    "high": "orange1",
                    "medium": "yellow",
                    "low": "blue"
                }.get(finding.severity, "white")

                console.print(f"[bold]{i}. {finding.attack_name}[/bold]")
                console.print(f"   Severity: [{severity_color}]{finding.severity.upper()}[/{severity_color}]")
                console.print(f"   Payload: [dim]{finding.payload[:60]}...[/dim]")
                console.print(f"   Response: [dim]{finding.response[:60]}...[/dim]")
                console.print()

            if len(results["findings"]) > 5:
                console.print(f"[dim]... and {len(results['findings']) - 5} more vulnerabilities[/dim]\n")
    else:
        console.print("[green bold]No vulnerabilities found[/green bold]\n")

    if results["vulnerable"] > 0:
        console.print(Panel(
            "[yellow]Recommendation:[/yellow]\n\n"
            "Your agent has security vulnerabilities. Consider:\n"
            "• Implementing input validation\n"
            "• Adding output filtering\n"
            "• Using prompt templates with restricted variables",
            title="[yellow]Next Steps[/yellow]",
            border_style="yellow"
        ))
