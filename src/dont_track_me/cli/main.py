"""CLI entry point — the `dtm` command."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import webbrowser
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from dont_track_me.core.agent import get_agent_db, get_app_scan_results, get_dns_events
from dont_track_me.core.auth import (
    REDIRECT_URI,
    AuthenticationRequired,
    OAuthFlow,
    OAuthModule,
    TokenStore,
    get_platform_credentials,
)
from dont_track_me.core.base import AuditResult, ThreatLevel
from dont_track_me.core.config import get_default_country
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
from dont_track_me.modules.search_noise.protector import protect_search_noise
from dont_track_me.modules.social_noise.protector import protect_social_noise

# Platform OAuth configurations
OAUTH_CONFIGS: dict[str, dict[str, Any]] = {
    "reddit": {
        "authorize_url": "https://www.reddit.com/api/v1/authorize",
        "token_url": "https://www.reddit.com/api/v1/access_token",
        "scopes": ["identity", "mysubreddits", "read", "account", "edit"],
        "extra_params": {"response_type": "code", "duration": "permanent"},
    },
    "youtube": {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "scopes": ["https://www.googleapis.com/auth/youtube"],
        "extra_params": {"access_type": "offline", "prompt": "consent"},
    },
}

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


def _run_interactive_checklist(checks: list[Any], module_name: str) -> dict[str, bool]:
    """Prompt user through a privacy checklist and collect yes/no responses."""
    threat_styles = {
        ThreatLevel.CRITICAL: "red bold",
        ThreatLevel.HIGH: "red",
        ThreatLevel.MEDIUM: "yellow",
        ThreatLevel.LOW: "blue",
    }

    console.print(
        Panel(
            f"[bold]Privacy Checklist — {module_name}[/bold]\n"
            "Answer each question about your current settings.",
            style="blue",
        )
    )

    responses: dict[str, bool] = {}
    for i, check in enumerate(checks, 1):
        style = threat_styles.get(check.threat_level, "dim")
        console.print(
            f"\n[{style}][{check.threat_level.value.upper()}][/{style}] "
            f"({i}/{len(checks)}) {check.question}"
        )
        console.print(f"  [dim]{check.description}[/dim]")
        console.print(f"  [dim]Fix: {check.remediation}[/dim]")
        if check.technical_countermeasure:
            console.print(f"  [dim]Enforce: {check.technical_countermeasure}[/dim]")

        while True:
            answer = click.prompt("  (y/n)", type=str, default="").strip().lower()
            if answer in ("y", "yes"):
                responses[check.id] = True
                break
            elif answer in ("n", "no"):
                responses[check.id] = False
                break
            else:
                console.print("  [yellow]Please answer y or n[/yellow]")

    console.print()
    return responses


def _render_audit_result(result: AuditResult) -> None:
    """Render a single module's audit result with Rich."""
    color = get_score_color(result.score)
    label = get_score_label(result.score)

    console.print(
        f"\n[bold]{result.module_name}[/bold] — [{color}]{result.score}/100 ({label})[/{color}]"
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
    "--format", "output_format", type=click.Choice(["rich", "json", "html"]), default="rich"
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output file path (for html format). Defaults to a temp file.",
)
@click.option(
    "--interactive",
    "-i",
    is_flag=True,
    help="Answer privacy checklists interactively (for checklist-based modules).",
)
def audit(
    module_name: str | None,
    modules: str | None,
    output_format: str,
    output: str | None,
    interactive: bool,
) -> None:
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
            raise SystemExit(1)
        if not mod.is_available():
            console.print(f"[red]Module '{module_name}' dependencies not installed.[/red]")
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
                console.print(f"[yellow]Skipping {name} (dependencies not installed)[/yellow]")
                continue
            targets[name] = mod
    else:
        targets = available

    async def _run_audits() -> list[AuditResult]:
        results = []
        for name, mod in targets.items():
            kwargs: dict[str, Any] = {}

            # Interactive checklist for modules that support it
            checklist = mod.get_checklist() if interactive else None
            if checklist is not None:
                responses = _run_interactive_checklist(checklist, name)
                kwargs["responses"] = responses

            try:
                result = await mod.audit(**kwargs)
                results.append(result)
            except AuthenticationRequired as e:
                if module_name:
                    # User explicitly requested this module — show error
                    console.print(f"[red]Not authenticated. Run: dtm auth {e.platform}[/red]")
                    sys.exit(1)
                else:
                    console.print(
                        f"[dim]Skipping {name} (not authenticated — run dtm auth {e.platform})[/dim]"
                    )
        return results

    results = _run_async(_run_audits())

    overall = compute_overall_score(results)

    if output_format == "json":
        data = [r.model_dump() for r in results]
        click.echo(json.dumps(data, indent=2))
    elif output_format == "html":
        from dont_track_me.core.report import generate_html_report

        html_content = generate_html_report(results, overall)
        if output:
            report_path = Path(output)
            report_path.write_text(html_content)
        else:
            fd, tmp = tempfile.mkstemp(suffix=".html", prefix="dtm-report-")
            with open(fd, "w") as f:
                f.write(html_content)
            report_path = Path(tmp)
        console.print(f"[green]Report saved to {report_path}[/green]")
        webbrowser.open(report_path.as_uri())
    else:
        console.print(Panel("[bold]Privacy Audit Results[/bold]", style="blue"))
        for result in results:
            _render_audit_result(result)
        color = get_score_color(overall)
        label = get_score_label(overall)
        console.print(f"\n[bold]Overall Score:[/bold] [{color}]{overall}/100 ({label})[/{color}]\n")


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
@click.option("--harden-only", is_flag=True, help="Only harden privacy settings (reddit).")
@click.option(
    "--diversify-only",
    is_flag=True,
    help="Only diversify subscriptions (reddit/youtube).",
)
def protect(
    module_name: str | None,
    apply_: bool,
    path: str | None,
    harden_only: bool,
    diversify_only: bool,
) -> None:
    """Apply privacy protections. Dry-run by default — use --apply to execute."""
    available = get_available_modules()
    dry_run = not apply_

    if module_name:
        mod = get_module(module_name)
        if mod is None or not mod.is_available():
            console.print(f"[red]Module '{module_name}' not available.[/red]")
            raise SystemExit(1)
        targets = {module_name: mod}
    else:
        targets = available

    if dry_run:
        console.print(
            "[yellow]Dry-run mode — no changes will be made. Use --apply to execute.[/yellow]\n"
        )

    async def _run_protections() -> list:
        results = []
        for name, mod in targets.items():
            kwargs: dict[str, Any] = {}
            if path:
                kwargs["path"] = path
            if harden_only:
                kwargs["harden_only"] = True
            if diversify_only:
                kwargs["diversify_only"] = True
            try:
                result = await mod.protect(dry_run=dry_run, **kwargs)
                results.append(result)
            except AuthenticationRequired as e:
                if module_name:
                    console.print(f"[red]Not authenticated. Run: dtm auth {e.platform}[/red]")
                    sys.exit(1)
                else:
                    console.print(
                        f"[dim]Skipping {name} (not authenticated — run dtm auth {e.platform})[/dim]"
                    )
        return results

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
        raise SystemExit(1)

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
        results = []
        for _name, mod in available.items():
            try:
                result = await mod.audit()
                results.append(result)
            except AuthenticationRequired:
                pass  # Silently skip in score view
        return results

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
def auth() -> None:
    """Authenticate with social media platforms."""


@auth.command("status")
def auth_status() -> None:
    """Show authentication status for all platforms."""
    table = Table(title="Authentication Status")
    table.add_column("Platform", style="bold")
    table.add_column("Authenticated", justify="center")
    table.add_column("Token Expiry")

    for platform in sorted(OAUTH_CONFIGS.keys()):
        token = TokenStore.load(platform)
        if token is None:
            table.add_row(platform, "[red]no[/red]", "-")
        elif token.is_expired:
            table.add_row(platform, "[yellow]expired[/yellow]", "Expired")
        else:
            if token.expires_at:
                remaining = token.expires_at - time.time()
                hours = int(remaining // 3600)
                minutes = int((remaining % 3600) // 60)
                expiry = f"{hours}h {minutes}m remaining"
            else:
                expiry = "No expiry"
            table.add_row(platform, "[green]yes[/green]", expiry)

    console.print(table)


@auth.command("revoke")
@click.argument("platform")
def auth_revoke(platform: str) -> None:
    """Revoke authentication for a platform."""
    if platform not in OAUTH_CONFIGS:
        console.print(
            f"[red]Unknown platform: {platform}. Available: {', '.join(OAUTH_CONFIGS.keys())}[/red]"
        )
        sys.exit(1)

    TokenStore.delete(platform)
    console.print(f"[green]Revoked authentication for {platform}.[/green]")


def _auth_platform(platform: str) -> None:
    """Run OAuth flow for a platform."""
    if platform not in OAUTH_CONFIGS:
        console.print(
            f"[red]Unknown platform: {platform}. Available: {', '.join(OAUTH_CONFIGS.keys())}[/red]"
        )
        sys.exit(1)

    config = OAUTH_CONFIGS[platform]

    try:
        client_id, client_secret = get_platform_credentials(platform)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(f"Opening browser for {platform} authentication...")
    console.print(f"[dim]Redirect URI: {REDIRECT_URI}[/dim]\n")

    try:
        flow = OAuthFlow(
            authorize_url=config["authorize_url"],
            token_url=config["token_url"],
            client_id=client_id,
            client_secret=client_secret,
            scopes=config["scopes"],
            extra_params=config.get("extra_params", {}),
        )
        token = flow.run()
        TokenStore.save(platform, token)
        console.print(f"\n[green]Successfully authenticated with {platform}![/green]")
    except Exception as e:
        console.print(f"\n[red]Authentication failed: {e}[/red]")
        sys.exit(1)


@auth.command("reddit")
def auth_reddit() -> None:
    """Authenticate with Reddit."""
    _auth_platform("reddit")


@auth.command("youtube")
def auth_youtube() -> None:
    """Authenticate with YouTube."""
    _auth_platform("youtube")


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
@click.option("--categories", "-c", help="Comma-separated categories (e.g. politics,religion).")
@click.option("--count", "-n", default=50, help="Number of queries to generate.")
@click.option("--engines", "-e", help="Comma-separated engines (e.g. google,bing).")
@click.option(
    "--country",
    "-C",
    default=None,
    help="Country code for localized queries (e.g. us, fr). Default from config or 'us'.",
)
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
    country: str | None,
    dry_run_flag: bool,
) -> None:
    """Generate balanced search queries to poison your search profile."""
    if country is None:
        country = get_default_country()

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
            country=country,
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
@click.option("--platforms", "-p", help="Comma-separated platforms (e.g. instagram,youtube).")
@click.option("--categories", "-c", help="Comma-separated categories (e.g. politics,music).")
@click.option("--per-subcategory", default=2, help="Accounts to pick per perspective.")
@click.option(
    "--country",
    "-C",
    default=None,
    help="Country code for localized accounts (e.g. us, fr). Default from config or 'us'.",
)
@click.option("--format", "output_format", type=click.Choice(["rich", "json"]), default="rich")
def noise_social(
    apply_: bool,
    platforms: str | None,
    categories: str | None,
    per_subcategory: int,
    country: str | None,
    output_format: str,
) -> None:
    """Generate balanced follow lists to obfuscate your social media profile."""
    if country is None:
        country = get_default_country()

    dry_run = not apply_

    if dry_run:
        console.print("[yellow]Dry-run mode — use --apply to generate follow lists.[/yellow]\n")

    async def _run() -> None:
        result = await protect_social_noise(
            dry_run=dry_run,
            platforms=platforms,
            categories=categories,
            per_subcategory=per_subcategory,
            output_format=output_format,
            country=country,
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
                console.print(Panel("[bold]Follow These Accounts[/bold]", style="green"))
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
@click.option("--format", "output_format", type=click.Choice(["rich", "json"]), default="rich")
def apps(output_format: str) -> None:
    """Show tracking SDK analysis of installed applications (from dtm-agent)."""
    db = get_agent_db()
    if db is None:
        console.print("[yellow]No dtm-agent data found.[/yellow]")
        console.print("Run the Rust agent first:")
        console.print("  [bold]cd agent && cargo build --release[/bold]")
        console.print("  [bold]./target/release/dtm-agent scan-apps[/bold]")
        return

    results = get_app_scan_results(db)
    if not results:
        console.print("[yellow]No app scan results. Run: dtm-agent scan-apps[/yellow]")
        return

    if output_format == "json":
        click.echo(json.dumps(results, indent=2))
        return

    with_trackers = [r for r in results if r["tracking_sdks"]]
    with_ats = [r for r in results if r["ats_exceptions"]]

    console.print(Panel("[bold]App Tracking SDK Analysis[/bold]", style="blue"))
    console.print(f"Applications scanned: {len(results)}")
    console.print(
        f"With tracking SDKs:   [red]{len(with_trackers)}[/red] "
        f"({len(with_trackers) * 100 // max(len(results), 1)}%)"
    )
    console.print(f"With ATS exceptions:  [yellow]{len(with_ats)}[/yellow]")

    if with_trackers:
        console.print("\n[bold]Apps with Tracking SDKs:[/bold]")
        table = Table()
        table.add_column("Application", style="bold")
        table.add_column("Bundle ID", style="dim")
        table.add_column("Tracking SDKs", style="red")

        for app in with_trackers:
            sdk_names = ", ".join(s["name"] for s in app["tracking_sdks"])
            table.add_row(
                app["app_name"],
                app["bundle_id"] or "unknown",
                sdk_names,
            )
        console.print(table)

    if with_ats:
        console.print("\n[bold]Apps with ATS Exceptions:[/bold]")
        table = Table()
        table.add_column("Application", style="bold")
        table.add_column("Exceptions", style="yellow")

        for app in with_ats:
            table.add_row(
                app["app_name"],
                "; ".join(app["ats_exceptions"]),
            )
        console.print(table)

    if not with_trackers and not with_ats:
        console.print("\n[green]No tracking SDKs or ATS exceptions found.[/green]")


@cli.command()
@click.option("--tracker-only", is_flag=True, help="Only show tracker DNS queries.")
@click.option("--limit", "-n", default=50, help="Number of events to show.")
@click.option("--format", "output_format", type=click.Choice(["rich", "json"]), default="rich")
def monitor(tracker_only: bool, limit: int, output_format: str) -> None:
    """Show DNS tracking events captured by dtm-agent."""
    db = get_agent_db()
    if db is None:
        console.print("[yellow]No dtm-agent data found.[/yellow]")
        console.print("Run the Rust agent first:")
        console.print("  [bold]cd agent && cargo build --release[/bold]")
        console.print("  [bold]sudo ./target/release/dtm-agent monitor-dns[/bold]")
        return

    events = get_dns_events(db, tracker_only=tracker_only, limit=limit)
    if not events:
        msg = "No tracker DNS events" if tracker_only else "No DNS events"
        console.print(f"[yellow]{msg} recorded yet.[/yellow]")
        console.print("Start the DNS monitor: [bold]sudo dtm-agent monitor-dns[/bold]")
        return

    if output_format == "json":
        click.echo(json.dumps(events, indent=2))
        return

    tracker_count = sum(1 for e in events if e["is_tracker"])
    console.print(Panel("[bold]DNS Tracking Monitor[/bold]", style="blue"))
    console.print(f"Showing {len(events)} events ({tracker_count} tracker queries)\n")

    table = Table()
    table.add_column("Time", style="dim")
    table.add_column("Type")
    table.add_column("Domain")
    table.add_column("Category")
    table.add_column("Process")

    for event in events:
        ts = event["timestamp"][:19].replace("T", " ")
        style = "red" if event["is_tracker"] else ""
        table.add_row(
            ts,
            event["query_type"],
            f"[{style}]{event['domain']}[/{style}]" if style else event["domain"],
            event.get("tracker_category") or "",
            event.get("process_name") or "",
        )

    console.print(table)


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
    table.add_column("Auth", justify="center")
    table.add_column("Dependencies")

    for name, mod in sorted(all_modules.items()):
        available = mod.is_available()
        deps = ", ".join(mod.get_dependencies()) or "none"
        status_icon = "[green]yes[/green]" if available else "[red]no[/red]"

        # Auth status for OAuth modules
        if isinstance(mod, OAuthModule):
            auth_icon = "[green]yes[/green]" if mod.is_authenticated() else "[red]no[/red]"
        else:
            auth_icon = "[dim]-[/dim]"

        table.add_row(name, mod.description, status_icon, auth_icon, deps)

    console.print(table)
