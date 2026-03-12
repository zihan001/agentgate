"""Stdio MCP proxy — spawns MCP server as child process, relays LSP-framed messages bidirectionally."""

from __future__ import annotations

import asyncio
import logging
import sys

log = logging.getLogger("agentgate.proxy")


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

    def __init__(self, command: list[str]) -> None:
        self.command = command

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
        agent_to_server = asyncio.create_task(_relay(agent_reader, child.stdin, "agent->server"))
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
