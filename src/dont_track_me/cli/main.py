"""CLI entry point — the `dtm` command."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dont_track_me.core.base import AuditResult, ThreatLevel
from dont_track_me.core.registry import (
    get_all_modules,
    get_available_modules,
    get_module,
)
from dont_track_me.core.scoring import (
    compute_overall_score,
    get_score_color,
    get_score_label,
)

console = Console()

THREAT_COLORS = {
    ThreatLevel.CRITICAL: "red bold",
    ThreatLevel.HIGH: "red",
    ThreatLevel.MEDIUM: "yellow",
    ThreatLevel.LOW: "blue",
    ThreatLevel.INFO: "dim",
}


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from sync Click commands."""
    return asyncio.run(coro)


def _render_audit_result(result: AuditResult) -> None:
    """Render a single module's audit result with Rich."""
    color = get_score_color(result.score)
    label = get_score_label(result.score)

    console.print(
        f"\n[bold]{result.module_name}[/bold] — "
        f"[{color}]{result.score}/100 ({label})[/{color}]"
    )

    if not result.findings:
        console.print("  [green]No issues found.[/green]")
        return

    for finding in result.findings:
        style = THREAT_COLORS.get(finding.threat_level, "")
        console.print(
            f"  [{style}][{finding.threat_level.value.upper()}][/{style}] {finding.title}"
        )
        console.print(f"    {finding.description}")
        console.print(f"    [dim]Remediation:[/dim] {finding.remediation}")


@click.group()
@click.version_option(package_name="dont-track-me")
def cli() -> None:
    """dtm — Don't Track Me. Audit and protect your digital privacy."""


@cli.command()
@click.argument("module_name", required=False)
@click.option("--modules", "-m", help="Comma-separated list of modules to audit.")
@click.option(
    "--format", "output_format", type=click.Choice(["rich", "json"]), default="rich"
)
def audit(module_name: str | None, modules: str | None, output_format: str) -> None:
    """Run privacy audits. Optionally specify a single module or --modules list."""
    available = get_available_modules()

    if not available:
        console.print("[red]No modules available. Install optional dependencies.[/red]")
        sys.exit(1)

    # Determine which modules to run
    if module_name:
        mod = get_module(module_name)
        if mod is None:
            console.print(f"[red]Unknown module: {module_name}[/red]")
            sys.exit(1)
        if not mod.is_available():
            console.print(
                f"[red]Module '{module_name}' dependencies not installed.[/red]"
            )
            sys.exit(1)
        targets = {module_name: mod}
    elif modules:
        targets = {}
        for name in modules.split(","):
            name = name.strip()
            mod = get_module(name)
            if mod is None:
                console.print(f"[yellow]Skipping unknown module: {name}[/yellow]")
                continue
            if not mod.is_available():
                console.print(
                    f"[yellow]Skipping {name} (dependencies not installed)[/yellow]"
                )
                continue
            targets[name] = mod
    else:
        targets = available

    async def _run_audits() -> list[AuditResult]:
        tasks = [mod.audit() for mod in targets.values()]
        return await asyncio.gather(*tasks)

    results = _run_async(_run_audits())

    if output_format == "json":
        data = [r.model_dump() for r in results]
        click.echo(json.dumps(data, indent=2))
    else:
        console.print(Panel("[bold]Privacy Audit Results[/bold]", style="blue"))
        for result in results:
            _render_audit_result(result)
        overall = compute_overall_score(results)
        color = get_score_color(overall)
        label = get_score_label(overall)
        console.print(
            f"\n[bold]Overall Score:[/bold] [{color}]{overall}/100 ({label})[/{color}]\n"
        )


@cli.command()
@click.argument("module_name", required=False)
@click.option(
    "--apply",
    "apply_",
    is_flag=True,
    help="Actually apply changes (default is dry-run).",
)
@click.option(
    "--path",
    type=click.Path(exists=True),
    help="Path for file-based modules (e.g. metadata).",
)
def protect(module_name: str | None, apply_: bool, path: str | None) -> None:
    """Apply privacy protections. Dry-run by default — use --apply to execute."""
    available = get_available_modules()
    dry_run = not apply_

    if module_name:
        mod = get_module(module_name)
        if mod is None or not mod.is_available():
            console.print(f"[red]Module '{module_name}' not available.[/red]")
            sys.exit(1)
        targets = {module_name: mod}
    else:
        targets = available

    if dry_run:
        console.print(
            "[yellow]Dry-run mode — no changes will be made. Use --apply to execute.[/yellow]\n"
        )

    async def _run_protections() -> list:
        kwargs: dict[str, Any] = {}
        if path:
            kwargs["path"] = path
        tasks = [mod.protect(dry_run=dry_run, **kwargs) for mod in targets.values()]
        return await asyncio.gather(*tasks)

    results = _run_async(_run_protections())

    for result in results:
        console.print(f"\n[bold]{result.module_name}[/bold]")
        if result.dry_run:
            if result.actions_available:
                console.print("  Actions available (dry-run):")
                for action in result.actions_available:
                    console.print(f"    [yellow]- {action}[/yellow]")
            else:
                console.print("  [green]No actions needed.[/green]")
        else:
            if result.actions_taken:
                console.print("  Actions applied:")
                for action in result.actions_taken:
                    console.print(f"    [green]- {action}[/green]")
            else:
                console.print("  [green]No actions needed.[/green]")


@cli.command()
@click.argument("module_name")
def info(module_name: str) -> None:
    """Show educational content about a tracking vector."""
    mod = get_module(module_name)
    if mod is None:
        console.print(f"[red]Unknown module: {module_name}[/red]")
        sys.exit(1)

    from rich.markdown import Markdown

    content = mod.get_educational_content()
    console.print(Panel(f"[bold]{mod.display_name}[/bold]", style="blue"))
    console.print(Markdown(content))


@cli.command()
def score() -> None:
    """Show your overall trackability score."""
    available = get_available_modules()

    if not available:
        console.print("[red]No modules available.[/red]")
        sys.exit(1)

    async def _run_audits() -> list[AuditResult]:
        tasks = [mod.audit() for mod in available.values()]
        return await asyncio.gather(*tasks)

    results = _run_async(_run_audits())
    overall = compute_overall_score(results)
    color = get_score_color(overall)
    label = get_score_label(overall)

    console.print(
        Panel(
            f"[{color} bold]{overall}/100[/{color} bold]\n[{color}]{label}[/{color}]",
            title="[bold]Privacy Score[/bold]",
            subtitle="Higher is better",
            style="blue",
        )
    )

    # Per-module breakdown
    table = Table(title="Module Breakdown")
    table.add_column("Module", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Status")

    for result in sorted(results, key=lambda r: r.score):
        c = get_score_color(result.score)
        table.add_row(
            result.module_name,
            f"[{c}]{result.score}/100[/{c}]",
            f"[{c}]{get_score_label(result.score)}[/{c}]",
        )

    console.print(table)


@cli.group()
def noise() -> None:
    """Generate noise to obfuscate your digital profile."""


@noise.command("search")
@click.option(
    "--apply",
    "apply_",
    is_flag=True,
    help="Actually send search queries (default is dry-run).",
)
@click.option(
    "--categories", "-c", help="Comma-separated categories (e.g. politics,religion)."
)
@click.option("--count", "-n", default=50, help="Number of queries to generate.")
@click.option("--engines", "-e", help="Comma-separated engines (e.g. google,bing).")
@click.option(
    "--dry-run",
    "dry_run_flag",
    is_flag=True,
    default=False,
    help="Preview without sending (default behavior).",
)
def noise_search(
    apply_: bool,
    categories: str | None,
    count: int,
    engines: str | None,
    dry_run_flag: bool,
) -> None:
    """Generate balanced search queries to poison your search profile."""
    from dont_track_me.modules.search_noise.protector import protect_search_noise

    dry_run = not apply_

    if dry_run:
        console.print(
            "[yellow]Dry-run mode — no queries will be sent. Use --apply to execute.[/yellow]\n"
        )

    async def _run() -> None:
        result = await protect_search_noise(
            dry_run=dry_run,
            categories=categories,
            count=count,
            engines=engines,
        )

        if result.dry_run:
            console.print(Panel("[bold]Search Noise — Preview[/bold]", style="blue"))
            for action in result.actions_available:
                if action.startswith("---"):
                    console.print(f"\n[bold]{action}[/bold]")
                elif action.startswith("  "):
                    console.print(f"  [dim]{action.strip()}[/dim]")
                else:
                    console.print(f"  {action}")
        else:
            console.print(Panel("[bold]Search Noise — Executed[/bold]", style="green"))
            for action in result.actions_taken:
                console.print(f"  [green]{action}[/green]")
            console.print(f"\n[bold]Sent {len(result.actions_taken)} queries.[/bold]")

    _run_async(_run())


@noise.command("social")
@click.option(
    "--apply",
    "apply_",
    is_flag=True,
    help="Generate follow lists (default is dry-run).",
)
@click.option(
    "--platforms", "-p", help="Comma-separated platforms (e.g. instagram,youtube)."
)
@click.option(
    "--categories", "-c", help="Comma-separated categories (e.g. politics,music)."
)
@click.option("--per-subcategory", default=2, help="Accounts to pick per perspective.")
@click.option(
    "--format", "output_format", type=click.Choice(["rich", "json"]), default="rich"
)
def noise_social(
    apply_: bool,
    platforms: str | None,
    categories: str | None,
    per_subcategory: int,
    output_format: str,
) -> None:
    """Generate balanced follow lists to obfuscate your social media profile."""
    from dont_track_me.modules.social_noise.protector import protect_social_noise

    dry_run = not apply_

    if dry_run:
        console.print(
            "[yellow]Dry-run mode — use --apply to generate follow lists.[/yellow]\n"
        )

    async def _run() -> None:
        result = await protect_social_noise(
            dry_run=dry_run,
            platforms=platforms,
            categories=categories,
            per_subcategory=per_subcategory,
            output_format=output_format,
        )

        if result.dry_run:
            console.print(Panel("[bold]Social Noise — Strategy[/bold]", style="blue"))
            for action in result.actions_available:
                console.print(f"  {action}")
        else:
            if output_format == "json":
                # JSON output goes to stdout raw
                for action in result.actions_taken:
                    click.echo(action)
            else:
                console.print(
                    Panel("[bold]Follow These Accounts[/bold]", style="green")
                )
                for action in result.actions_taken:
                    if action.startswith("---"):
                        console.print(f"\n[bold]{action}[/bold]")
                    elif action.startswith("  ["):
                        console.print(f"  [blue]{action.strip()}[/blue]")
                    elif action.startswith("    "):
                        console.print(f"    {action.strip()}")
                    elif action.startswith("\n"):
                        console.print(f"\n[bold]{action.strip()}[/bold]")
                    else:
                        console.print(f"  {action}")

    _run_async(_run())


@cli.command()
def status() -> None:
    """Show available modules and their dependency status."""
    all_modules = get_all_modules()

    if not all_modules:
        console.print("[yellow]No modules discovered.[/yellow]")
        return

    table = Table(title="Module Status")
    table.add_column("Module", style="bold")
    table.add_column("Description")
    table.add_column("Available", justify="center")
    table.add_column("Dependencies")

    for name, mod in sorted(all_modules.items()):
        available = mod.is_available()
        deps = ", ".join(mod.get_dependencies()) or "none"
        status_icon = "[green]yes[/green]" if available else "[red]no[/red]"
        table.add_row(name, mod.description, status_icon, deps)

    console.print(table)
