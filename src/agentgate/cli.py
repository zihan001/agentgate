"""Click CLI entry point — init, start, logs commands."""

import logging
import os
import sys

import click

from agentgate import __version__


def _setup_logging(verbose: bool) -> None:
    """Configure logging for the agentgate namespace."""
    level = logging.DEBUG if verbose else logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s: %(message)s"))
    logger = logging.getLogger("agentgate")
    logger.setLevel(level)
    logger.addHandler(handler)


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
    default=None,
    type=click.Path(),
    help="Path to the policy file. Default: $AGENTGATE_POLICY or agentgate.yaml.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
@click.argument("server_command", nargs=-1, required=True)
def start(policy: str | None, verbose: bool, server_command: tuple[str, ...]) -> None:
    """Start the AgentGate proxy wrapping an MCP server.

    Usage: agentgate start [--policy FILE] [--verbose] -- <command> [args...]
    """
    import asyncio
    from pathlib import Path

    from agentgate.proxy import StdioProxy

    _setup_logging(verbose)

    # --- Validate server command ---
    if not server_command:
        click.echo(
            "Error: No server command provided.\nUsage: agentgate start -- <command> [args...]",
            err=True,
        )
        raise SystemExit(1)

    # --- Resolve policy path ---
    if policy is None:
        policy = os.environ.get("AGENTGATE_POLICY", "agentgate.yaml")
    policy_path = Path(policy)

    # --- Load policy ---
    compiled_policy = None
    if policy_path.exists():
        from agentgate.policy import PolicyLoadError, load_and_compile

        try:
            compiled_policy = load_and_compile(policy_path)
        except PolicyLoadError as e:
            click.echo(f"Error loading policy: {e}", err=True)
            raise SystemExit(1)

    # --- Startup banner ---
    mode = "enforcing" if compiled_policy is not None else "passthrough"
    policy_display = str(policy_path) if compiled_policy else "(none)"
    rule_count = len(compiled_policy.config.policies) if compiled_policy else 0
    click.echo(
        f"AgentGate v{__version__} | mode={mode} | policy={policy_display} "
        f"| rules={rule_count} | server={server_command[0]}",
        err=True,
    )

    # --- Run proxy ---
    proxy = StdioProxy(list(server_command), policy=compiled_policy)
    try:
        exit_code = asyncio.run(proxy.run())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except FileNotFoundError:
        click.echo(
            f"Error: Command not found: '{server_command[0]}'. Is it installed and on your PATH?",
            err=True,
        )
        raise SystemExit(1)
    except PermissionError:
        click.echo(
            f"Error: Permission denied running: '{server_command[0]}'.",
            err=True,
        )
        raise SystemExit(1)
    raise SystemExit(exit_code)


@main.command()
@click.option("--tail", type=int, help="Show last N entries.")
@click.option("--session", type=str, help="Filter by session ID.")
@click.option("--decision", type=click.Choice(["allow", "block"]), help="Filter by decision.")
def logs(tail: int | None, session: str | None, decision: str | None) -> None:
    """Query the audit log."""
    click.echo("Not yet implemented. Coming in PR2.")
