"""Click CLI entry point — init, start, logs commands."""

import click

from agentgate import __version__


@click.group()
@click.version_option(version=__version__, prog_name="agentgate")
def main() -> None:
    """AgentGate — tool-call policy engine and runtime proxy for AI agents."""


@main.command()
def init() -> None:
    """Generate a starter agentgate.yaml policy file."""
    click.echo("Not yet implemented. Coming in PR1.")


@main.command()
@click.option(
    "--policy",
    default="agentgate.yaml",
    type=click.Path(),
    help="Path to the policy file (default: agentgate.yaml).",
)
@click.argument("server_command", nargs=-1, required=True)
def start(policy: str, server_command: tuple[str, ...]) -> None:
    """Start the AgentGate proxy wrapping an MCP server.

    Usage: agentgate start -- npx -y @modelcontextprotocol/server-filesystem /data
    """
    import asyncio
    from pathlib import Path

    from agentgate.proxy import StdioProxy

    compiled_policy = None
    policy_path = Path(policy)
    if policy_path.exists():
        from agentgate.policy import PolicyLoadError, load_and_compile

        try:
            compiled_policy = load_and_compile(policy_path)
        except PolicyLoadError as e:
            click.echo(f"Error loading policy: {e}", err=True)
            raise SystemExit(1)

    proxy = StdioProxy(list(server_command), policy=compiled_policy)
    raise SystemExit(asyncio.run(proxy.run()))


@main.command()
@click.option("--tail", type=int, help="Show last N entries.")
@click.option("--session", type=str, help="Filter by session ID.")
@click.option("--decision", type=click.Choice(["allow", "block"]), help="Filter by decision.")
def logs(tail: int | None, session: str | None, decision: str | None) -> None:
    """Query the audit log."""
    click.echo("Not yet implemented. Coming in PR2.")
