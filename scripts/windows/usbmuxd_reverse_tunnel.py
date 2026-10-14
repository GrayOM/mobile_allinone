"""Expose Apple's Windows usbmuxd inside WSL2 through a reverse tunnel.

Apple Mobile Device Service listens on 127.0.0.1:27015 on Windows only, and
Windows Firewall blocks WSL -> Windows connections by default, while
Windows -> WSL connections work. So the tunnel is built backwards:

* ``hub`` (runs in WSL): listens on 127.0.0.1:27016 for usbmuxd clients
  (pymobiledevice3 --usbmux 127.0.0.1:27016, USBMUXD_SOCKET_ADDRESS, …) and
  on 0.0.0.0:27018 for the Windows agent.
* ``agent`` (runs with the Windows Python): keeps one control connection to
  the hub; for every client the hub announces, the agent opens a data
  connection to the hub and a connection to 127.0.0.1:27015, then pipes.

    # WSL
    .venv/bin/python scripts/windows/usbmuxd_reverse_tunnel.py hub
    # Windows (PowerShell / from WSL via interop)
    py -3.13 scripts\\windows\\usbmuxd_reverse_tunnel.py agent --hub 127.0.0.1:27018

Only loopback and the WSL-internal address are used; nothing is exposed to
the LAN. The agent accepts hub instructions only after a shared token
handshake printed by the hub (``--token`` to pin one).
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys

USBMUXD = ("127.0.0.1", 27015)
BUFFER = 65536


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(BUFFER)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class Hub:
    def __init__(self, client_port: int, agent_port: int, token: str):
        self.client_port = client_port
        self.agent_port = agent_port
        self.token = token
        self.control: asyncio.StreamWriter | None = None
        self.pending: dict[str, asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]]] = {}

    async def on_agent(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = (await reader.readline()).decode().strip()
        if not line.startswith("TOKEN ") or not secrets.compare_digest(line[6:], self.token):
            writer.close()
            return
        kind = (await reader.readline()).decode().strip()
        if kind == "CONTROL":
            self.control = writer
            print("[hub] agent control connected", flush=True)
            try:
                while await reader.readline():
                    pass
            finally:
                self.control = None
                print("[hub] agent control disconnected", flush=True)
            return
        if kind.startswith("DATA "):
            future = self.pending.pop(kind[5:], None)
            if future and not future.done():
                future.set_result((reader, writer))
                return
        writer.close()

    async def on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.control is None:
            print("[hub] client refused: agent not connected", flush=True)
            writer.close()
            return
        session = secrets.token_hex(8)
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self.pending[session] = future
        self.control.write(f"OPEN {session}\n".encode())
        try:
            await self.control.drain()
            agent_reader, agent_writer = await asyncio.wait_for(future, timeout=10)
        except Exception as exc:  # timeout or control failure
            self.pending.pop(session, None)
            print(f"[hub] client failed: {exc}", flush=True)
            writer.close()
            return
        await asyncio.gather(_pipe(reader, agent_writer), _pipe(agent_reader, writer))

    async def serve(self) -> None:
        agent_server = await asyncio.start_server(self.on_agent, "0.0.0.0", self.agent_port)
        client_server = await asyncio.start_server(self.on_client, "127.0.0.1", self.client_port)
        print(
            f"[hub] usbmuxd clients -> 127.0.0.1:{self.client_port} · agent port {self.agent_port} · token {self.token}",
            flush=True,
        )
        async with agent_server, client_server:
            await asyncio.gather(agent_server.serve_forever(), client_server.serve_forever())


async def run_agent(hub_host: str, hub_port: int, token: str) -> None:
    while True:
        try:
            reader, writer = await asyncio.open_connection(hub_host, hub_port)
        except OSError as exc:
            print(f"[agent] hub unreachable ({exc}); retrying", flush=True)
            await asyncio.sleep(3)
            continue
        writer.write(f"TOKEN {token}\nCONTROL\n".encode())
        await writer.drain()
        print(f"[agent] control connected to {hub_host}:{hub_port}", flush=True)
        try:
            while True:
                line = (await reader.readline()).decode().strip()
                if not line:
                    break
                if line.startswith("OPEN "):
                    asyncio.create_task(_open_session(hub_host, hub_port, token, line[5:]))
        finally:
            writer.close()
        print("[agent] control lost; reconnecting", flush=True)
        await asyncio.sleep(1)


async def _open_session(hub_host: str, hub_port: int, token: str, session: str) -> None:
    try:
        mux_reader, mux_writer = await asyncio.open_connection(*USBMUXD)
    except OSError as exc:
        print(f"[agent] usbmuxd unavailable: {exc}", flush=True)
        return
    try:
        hub_reader, hub_writer = await asyncio.open_connection(hub_host, hub_port)
    except OSError as exc:
        mux_writer.close()
        print(f"[agent] hub data connection failed: {exc}", flush=True)
        return
    hub_writer.write(f"TOKEN {token}\nDATA {session}\n".encode())
    await hub_writer.drain()
    await asyncio.gather(_pipe(hub_reader, mux_writer), _pipe(mux_reader, hub_writer))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="role", required=True)
    hub = sub.add_parser("hub")
    hub.add_argument("--client-port", type=int, default=27016)
    hub.add_argument("--agent-port", type=int, default=27018)
    hub.add_argument("--token", default=None)
    agent = sub.add_parser("agent")
    agent.add_argument("--hub", default="127.0.0.1:27018")
    agent.add_argument("--token", required=True)
    args = parser.parse_args()
    try:
        if args.role == "hub":
            token = args.token or secrets.token_hex(16)
            asyncio.run(Hub(args.client_port, args.agent_port, token).serve())
        else:
            host, _, port = args.hub.rpartition(":")
            asyncio.run(run_agent(host or "localhost", int(port), args.token))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
