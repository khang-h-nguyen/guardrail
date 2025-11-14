"""
GuardRail CLI - Main Entry Point
"""

import typer
from rich.console import Console

app = typer.Typer(
    name="guardrail",
    help="GuardRail - Security testing for AI agents",
    add_completion=False,
)

console = Console()

from .commands.scan import scan as scan_command

app.command(name="scan")(scan_command)


@app.command()
def version():
    """Show GuardRail version"""
    console.print("GuardRail v0.1.0", style="bold cyan")
    console.print("Security testing for AI agents", style="dim")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    GuardRail - Security testing for AI agents

    Test your AI agents for security vulnerabilities before deployment.
    """
    if ctx.invoked_subcommand is None:
        console.print("\n[bold cyan]GuardRail Security Scanner[/bold cyan]\n")
        console.print("Usage: [bold]guardrail [command][/bold]\n")
        console.print("Commands:")
        console.print("  [cyan]scan[/cyan]     - Run security scan on an agent")
        console.print("  [cyan]version[/cyan]  - Show version information")
        console.print("\nGet started: [bold]guardrail scan[/bold]\n")


if __name__ == "__main__":
    app()
