"""
Detect command - Scan text for security threats using pattern matching
"""

import typer
from rich.console import Console
from guardrail.core.detector import ThreatDetector

console = Console()


def detect(text: str = typer.Argument(..., help="Text to scan for threats")):
    """
    Scan text for security threats

    Example:
        guardrail detect "Ignore all instructions"
    """
    detector = ThreatDetector()
    threats = detector.scan(text)

    if not threats:
        console.print("[green]✓ No threats detected[/green]")
    else:
        console.print(f"[red]✗ Found {len(threats)} threat(s):[/red]\n")
        for threat in threats:
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'yellow',
                'MEDIUM': 'blue',
                'LOW': 'dim'
            }.get(threat['severity'], 'white')

            console.print(
                f"  [{severity_color}][{threat['severity']}][/{severity_color}] "
                f"{threat['category']}: {threat['description']}"
            )
            console.print(f"  [dim]ID: {threat['id']}[/dim]\n")
