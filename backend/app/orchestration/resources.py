from __future__ import annotations

import asyncio
import socket


class ResourceLeaseError(RuntimeError):
    pass


class ResourceLeaseManager:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._devices: dict[str, str] = {}
        self._ports: dict[int, str] = {}

    async def acquire(self, run_id: str, device_id: str, port: int | None) -> None:
        async with self._lock:
            device_owner = self._devices.get(device_id)
            if device_owner and device_owner != run_id:
                raise ResourceLeaseError(
                    f"단말 {device_id}은 진단 {device_owner}에서 사용 중입니다."
                )
            if port is not None:
                port_owner = self._ports.get(port)
                if port_owner and port_owner != run_id:
                    raise ResourceLeaseError(
                        f"프록시 포트 {port}은 진단 {port_owner}에서 사용 중입니다."
                    )
            self._devices[device_id] = run_id
            if port is not None:
                self._ports[port] = run_id

    async def release(self, run_id: str) -> None:
        async with self._lock:
            self._devices = {
                key: owner for key, owner in self._devices.items() if owner != run_id
            }
            self._ports = {
                key: owner for key, owner in self._ports.items() if owner != run_id
            }


def allocate_available_port(host: str) -> int:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((host, 0))
        return int(listener.getsockname()[1])
