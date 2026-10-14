"""Relay Apple's Windows usbmuxd (127.0.0.1:27015) to the WSL-facing interface.

Apple Mobile Device Service only listens on the Windows loopback address, so
WSL2 (NAT networking) cannot reach it. This relay binds a single TCP port on
the vEthernet (WSL) adapter address and forwards every connection to the
loopback usbmuxd. Run it with the Windows Python:

    py -3.13 scripts\\windows\\usbmuxd_relay.py --bind 172.17.128.1 --port 27016

Then, inside WSL:

    export USBMUXD_SOCKET_ADDRESS=172.17.128.1:27016   # libimobiledevice
    pymobiledevice3 --usbmux 172.17.128.1:27016 usbmux list

Bind only to the WSL adapter address (never 0.0.0.0): anyone who can reach
the relay can pair with and drive the connected phone.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys

UPSTREAM = ("127.0.0.1", 27015)


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    peer = client_writer.get_extra_info("peername")
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(*UPSTREAM)
    except OSError as exc:
        print(f"[relay] {peer} -> usbmuxd unavailable: {exc}", flush=True)
        client_writer.close()
        return
    await asyncio.gather(
        _pipe(client_reader, upstream_writer),
        _pipe(upstream_reader, client_writer),
    )


async def _serve(bind: str, port: int) -> None:
    server = await asyncio.start_server(_handle, bind, port)
    print(f"[relay] listening on {bind}:{port} -> {UPSTREAM[0]}:{UPSTREAM[1]}", flush=True)
    async with server:
        await server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind", required=True, help="WSL-facing adapter address, e.g. 172.17.128.1")
    parser.add_argument("--port", type=int, default=27016)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.bind)
    if address.is_unspecified:
        print("refusing to bind 0.0.0.0/:: — bind the WSL adapter address only", file=sys.stderr)
        return 2
    try:
        asyncio.run(_serve(args.bind, args.port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
