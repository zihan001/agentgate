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
@click.argument("server_command", nargs=-1, required=True)
def start(server_command: tuple[str, ...]) -> None:
    """Start the AgentGate proxy wrapping an MCP server.

    Usage: agentgate start -- npx -y @modelcontextprotocol/server-filesystem /data
    """
    click.echo("Not yet implemented. Coming in PR1.")


@main.command()
@click.option("--tail", type=int, help="Show last N entries.")
@click.option("--session", type=str, help="Filter by session ID.")
@click.option("--decision", type=click.Choice(["allow", "block"]), help="Filter by decision.")
def logs(tail: int | None, session: str | None, decision: str | None) -> None:
    """Query the audit log."""
    click.echo("Not yet implemented. Coming in PR2.")
