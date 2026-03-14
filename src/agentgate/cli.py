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
    import shutil
    from pathlib import Path

    dest = Path("agentgate.yaml")
    if dest.exists():
        click.echo(
            f"Error: {dest} already exists. Remove it first to regenerate.",
            err=True,
        )
        raise SystemExit(1)

    source = Path(__file__).parent / "agentgate.yaml.example"
    if not source.exists():
        click.echo("Error: Starter policy template not found in package.", err=True)
        raise SystemExit(1)

    shutil.copy2(source, dest)
    click.echo(f"Created {dest} — edit this file to define your policy.")


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
@click.option(
    "--audit-db",
    default="agentgate_audit.db",
    type=click.Path(),
    help="Path to the audit SQLite database. Default: agentgate_audit.db.",
)
@click.argument("server_command", nargs=-1, required=True)
def start(
    policy: str | None, verbose: bool, audit_db: str, server_command: tuple[str, ...]
) -> None:
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
    proxy = StdioProxy(
        list(server_command),
        policy=compiled_policy,
        audit_db=audit_db if compiled_policy else None,
    )
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
@click.option("--tail", type=click.IntRange(min=1), default=None, help="Show last N entries.")
@click.option("--session", type=str, default=None, help="Filter by session ID.")
@click.option(
    "--decision",
    type=click.Choice(["allow", "block"]),
    default=None,
    help="Filter by decision.",
)
@click.option(
    "--db",
    default="agentgate_audit.db",
    type=click.Path(),
    help="Path to audit database.",
)
@click.option(
    "--verify",
    is_flag=True,
    default=False,
    help="Verify hash chain integrity and exit.",
)
def logs(
    tail: int | None,
    session: str | None,
    decision: str | None,
    db: str,
    verify: bool,
) -> None:
    """Query the audit log."""
    import json
    import sqlite3
    from pathlib import Path

    db_path = Path(db)

    if not db_path.exists():
        click.echo(f"Error: Audit database not found: {db_path}", err=True)
        raise SystemExit(1)

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
    ).fetchall()
    if not tables:
        conn.close()
        click.echo(f"Error: No audit_log table in {db_path}", err=True)
        raise SystemExit(1)

    if verify:
        conn.close()
        from agentgate.audit import verify_chain

        valid, count = verify_chain(db_path)
        if valid:
            click.echo(f"OK: {count} entries, chain intact", err=True)
            raise SystemExit(0)
        else:
            click.echo(f"FAIL: chain broken ({count} entries examined)", err=True)
            raise SystemExit(1)

    # Build parameterized query
    conditions: list[str] = []
    params: list[str | int] = []

    if session is not None:
        conditions.append("session_id = ?")
        params.append(session)
    if decision is not None:
        conditions.append("decision = ?")
        params.append(decision)

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    columns = (
        "id, timestamp, session_id, tool_name, arguments, "
        "decision, matched_rule, matched_detector, message, "
        "prev_hash, entry_hash"
    )

    if tail is not None:
        sql = (
            f"SELECT * FROM ("
            f"SELECT {columns} FROM audit_log {where} "
            f"ORDER BY id DESC LIMIT ?"
            f") sub ORDER BY id ASC"
        )
        params.append(tail)
    else:
        sql = f"SELECT {columns} FROM audit_log {where} ORDER BY id ASC"

    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    column_names = [
        "id",
        "timestamp",
        "session_id",
        "tool_name",
        "arguments",
        "decision",
        "matched_rule",
        "matched_detector",
        "message",
        "prev_hash",
        "entry_hash",
    ]

    for row in rows:
        record: dict[str, object] = {}
        for col in column_names:
            val = row[col]
            if col == "arguments":
                try:
                    val = json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    pass
            record[col] = val
        click.echo(json.dumps(record, separators=(",", ":")))
