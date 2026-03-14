"""Stdio MCP proxy — spawns MCP server as child process, relays LSP-framed messages bidirectionally."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from agentgate.engine import evaluate
from agentgate.parser import build_error_response, parse_message
from agentgate.policy import CompiledPolicy
from agentgate.session import SessionEntry, SessionStore

log = logging.getLogger("agentgate.proxy")

_MAX_RESPONSE_TEXT = 10_000


def _extract_response_text(result: Any) -> str | None:
    """Extract human-readable text from an MCP tools/call result.

    Concatenates all text content items. Falls back to json.dumps().
    Truncates to _MAX_RESPONSE_TEXT characters for memory safety.
    """
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    t = item.get("text")
                    if isinstance(t, str):
                        texts.append(t)
            if texts:
                return "\n".join(texts)[:_MAX_RESPONSE_TEXT]
        return json.dumps(result)[:_MAX_RESPONSE_TEXT]
    if isinstance(result, str):
        return result[:_MAX_RESPONSE_TEXT]
    return json.dumps(result)[:_MAX_RESPONSE_TEXT]


async def read_message(reader: asyncio.StreamReader) -> bytes | None:
    """Read one LSP Content-Length framed message. Returns payload bytes or None on EOF."""
    content_length: int | None = None

    while True:
        line = await reader.readline()
        if not line:
            return None
        line_str = line.decode("ascii", errors="replace").strip()
        if not line_str:
            # Empty line = end of headers
            break
        if line_str.lower().startswith("content-length:"):
            content_length = int(line_str.split(":", 1)[1].strip())

    if content_length is None:
        return None

    try:
        payload = await reader.readexactly(content_length)
    except asyncio.IncompleteReadError:
        return None

    return payload


async def write_message(
    writer: asyncio.StreamWriter | asyncio.WriteTransport, payload: bytes
) -> None:
    """Write one LSP Content-Length framed message."""
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    writer.write(header + payload)
    if hasattr(writer, "drain"):
        await writer.drain()


async def _relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | asyncio.WriteTransport,
    label: str,
) -> None:
    """Relay LSP-framed messages from reader to writer until EOF."""
    while True:
        msg = await read_message(reader)
        if msg is None:
            log.debug("%s: EOF", label)
            break
        log.debug("%s: relayed %d bytes", label, len(msg))
        await write_message(writer, msg)


async def _intercepting_relay(
    reader: asyncio.StreamReader,
    server_writer: asyncio.StreamWriter | asyncio.WriteTransport,
    agent_writer: asyncio.StreamWriter | asyncio.WriteTransport,
    policy: CompiledPolicy,
    label: str,
    session: SessionStore,
    pending_responses: dict[str | int, SessionEntry],
) -> None:
    """Relay with policy interception: parse tool calls, evaluate, block or forward."""
    while True:
        payload = await read_message(reader)
        if payload is None:
            log.debug("%s: EOF", label)
            break

        parsed = parse_message(payload)

        if parsed.kind == "tool_call" and parsed.tool_call is not None:
            decision = evaluate(parsed.tool_call, policy, session)
            log.debug(
                "%s: %s -> %s (rule=%s)",
                label,
                parsed.tool_call.tool_name,
                decision.action,
                decision.matched_rule,
            )
            if decision.action == "block":
                error_data = {
                    "matched_rule": decision.matched_rule,
                    "matched_detector": decision.matched_detector,
                    "message": decision.message,
                }
                error_payload = build_error_response(
                    parsed.request_id, -32600, "Tool call blocked by policy", data=error_data
                )
                await write_message(agent_writer, error_payload)
                continue

            # Record allowed tool call in session store
            entry = session.record_request(
                parsed.tool_call.tool_name, parsed.tool_call.arguments
            )
            if parsed.request_id is not None:
                pending_responses[parsed.request_id] = entry

        # Allow: forward original bytes (zero re-serialization)
        log.debug("%s: forwarding %d bytes", label, len(payload))
        await write_message(server_writer, payload)


async def _response_intercepting_relay(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter | asyncio.WriteTransport,
    label: str,
    session: SessionStore,
    pending_responses: dict[str | int, SessionEntry],
) -> None:
    """Relay server→agent with response capture for session tracking."""
    while True:
        msg = await read_message(reader)
        if msg is None:
            log.debug("%s: EOF", label)
            break

        # Best-effort response capture — never break the relay
        try:
            parsed = json.loads(msg)
            req_id = parsed.get("id")
            if req_id is not None and req_id in pending_responses:
                entry = pending_responses.pop(req_id)
                result = parsed.get("result")
                if result is not None:
                    response_text = _extract_response_text(result)
                    if response_text is not None:
                        session.record_response(entry, response_text)
        except Exception:
            log.debug("%s: failed to parse response for session tracking, skipping", label)

        # Always forward original bytes unchanged
        await write_message(writer, msg)


async def _pipe_stderr(child_stderr: asyncio.StreamReader) -> None:
    """Pipe child stderr to proxy stderr, line by line."""
    while True:
        line = await child_stderr.readline()
        if not line:
            break
        sys.stderr.buffer.write(line)
        sys.stderr.buffer.flush()


class StdioProxy:
    """Transparent bidirectional MCP stdio proxy.

    Spawns an MCP server as a child process and relays LSP-framed
    messages between the parent's stdin/stdout and the child's
    stdin/stdout.
    """

    def __init__(self, command: list[str], policy: CompiledPolicy | None = None) -> None:
        self.command = command
        self.policy = policy
        self.session = SessionStore()
        self._pending_responses: dict[str | int, SessionEntry] = {}

    async def run(self) -> int:
        """Run the proxy. Returns the child process exit code."""
        loop = asyncio.get_running_loop()

        # Wrap agent-side stdin as async reader
        agent_reader = asyncio.StreamReader()
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(agent_reader),
            sys.stdin.buffer,
        )

        # Wrap agent-side stdout as async writer (returns WriteTransport)
        agent_write_transport, _ = await loop.connect_write_pipe(
            asyncio.BaseProtocol,
            sys.stdout.buffer,
        )

        # Spawn child MCP server process (no shell — args passed as list)
        child = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        log.debug("Spawned child process PID %d: %s", child.pid, self.command)

        # Create relay tasks
        if self.policy is not None:
            agent_to_server = asyncio.create_task(
                _intercepting_relay(
                    agent_reader,
                    child.stdin,
                    agent_write_transport,
                    self.policy,
                    "agent->server",
                    self.session,
                    self._pending_responses,
                )
            )
            server_to_agent = asyncio.create_task(
                _response_intercepting_relay(
                    child.stdout,
                    agent_write_transport,
                    "server->agent",
                    self.session,
                    self._pending_responses,
                )
            )
        else:
            agent_to_server = asyncio.create_task(
                _relay(agent_reader, child.stdin, "agent->server")
            )
            server_to_agent = asyncio.create_task(
                _relay(child.stdout, agent_write_transport, "server->agent")
            )
        stderr_task = asyncio.create_task(_pipe_stderr(child.stderr))

        # Wait for either relay to finish
        done, pending = await asyncio.wait(
            [agent_to_server, server_to_agent],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Re-raise exceptions from completed tasks
        for task in done:
            if task.exception():
                raise task.exception()

        # Clean shutdown
        if agent_to_server in done:
            # Agent closed stdin — signal child to stop
            child.stdin.close()
            await child.stdin.wait_closed()
        else:
            # Server closed — close agent stdout
            agent_write_transport.close()

        # Give the other relay a moment to finish, then cancel
        for task in pending:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Cancel stderr task
        stderr_task.cancel()
        try:
            await stderr_task
        except asyncio.CancelledError:
            pass

        # Wait for child to exit
        try:
            await asyncio.wait_for(child.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            log.warning("Child process did not exit in 5s, sending SIGTERM")
            child.terminate()
            try:
                await asyncio.wait_for(child.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                log.warning("Child did not exit after SIGTERM, sending SIGKILL")
                child.kill()
                await child.wait()

        return child.returncode or 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage: python -m agentgate.proxy <command> [args...]",
            file=sys.stderr,
        )
        sys.exit(1)
    proxy = StdioProxy(sys.argv[1:])
    sys.exit(asyncio.run(proxy.run()))
