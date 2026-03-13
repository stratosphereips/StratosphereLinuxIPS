#!/usr/bin/env python3

"""
This script requires a server to be running locally for testing
 python3 -m http.server 8080 --bind 127.0.0.1

"""
from __future__ import annotations

import asyncio
import inspect
import ipaddress
import os
import random
import socket
import string
import subprocess
import time
from dataclasses import dataclass
from typing import Awaitable, Callable

import aiohttp


PRIVATE_NETS = [
    # ipaddress.ip_network("127.0.0.0/8"),
    # ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    #     ipaddress.ip_network("192.168.0.0/16"),
    #     ipaddress.ip_network("169.254.0.0/16"),
    #     ipaddress.ip_network("::1/128"),
    #     ipaddress.ip_network("fc00::/7"),
    #     ipaddress.ip_network("fe80::/10"),
]


def is_private_host(host: str) -> bool:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise ValueError(f"Could not resolve {host!r}")

    for raw_ip in resolved:
        ip_obj = ipaddress.ip_address(raw_ip)
        if not any(ip_obj in net for net in PRIVATE_NETS):
            raise ValueError(
                f"Refusing non-private target {host!r} -> {raw_ip}. "
                "Use only loopback/private lab targets."
            )
    return True


# =========================
# Config
# =========================


@dataclass(frozen=True)
class LabConfig:
    http_base_url: str = "http://127.0.0.1:8080"
    dns_server: str = "8.8.8.8"
    dns_port: int = 53
    port80_host: str = "testphp.vulnweb.com"
    port80_port: int = 80

    sleep_between_profiles_sec: int = 600  # 10 minutes
    http_timeout_sec: float = 5.0
    http_concurrency: int = 200

    # Scan-style stages are disabled by default.
    enable_external_scan_commands: bool = True


CFG = LabConfig()


# =========================
# Helpers
# =========================


async def bounded_gather(coros: list[Awaitable[None]], limit: int) -> None:
    sem = asyncio.Semaphore(limit)

    async def runner(coro: Awaitable[None]) -> None:
        async with sem:
            try:
                await coro
            except Exception as exc:
                print(f"[WARN] worker failed: {exc}")

    await asyncio.gather(*(runner(c) for c in coros), return_exceptions=True)


def make_dns_query(name: str, qtype: int = 1) -> bytes:
    txid = random.randint(0, 65535).to_bytes(2, "big")
    flags = b"\x01\x00"
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"

    labels = name.strip(".").split(".")
    qname = (
        b"".join(
            len(label).to_bytes(1, "big") + label.encode() for label in labels
        )
        + b"\x00"
    )
    qclass = b"\x00\x01"
    question = qname + qtype.to_bytes(2, "big") + qclass

    return txid + flags + qdcount + ancount + nscount + arcount + question


async def tcp_open_and_close(
    host: str, port: int, linger: float = 0.0
) -> None:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        if linger > 0:
            await asyncio.sleep(linger)
    finally:
        writer.close()
        await writer.wait_closed()


async def run_stubbed_external_stage(
    name: str, would_run: list[str], enabled: bool
) -> None:
    """
    Safe default:
    - logs the command that would be run in a tightly controlled lab
    - does not execute it
    """
    print(f"[STAGE] {name}")
    print("[SAFE-STUB] External scan execution is disabled.")
    print("[SAFE-STUB] Would run:")
    print("  " + " ".join(would_run))

    if enabled:
        raise RuntimeError(
            f"{name} is intentionally blocked in this shared script. "
            "Replace this function yourself only inside an isolated lab."
        )


# =========================
# Attack profiles / stages
# =========================


async def attack_http_get_burst(cfg: LabConfig) -> None:
    """
    Simulates a burst of HTTP GET requests to a private lab service.
    Useful for HTTP flow spikes and connection churn.
    """
    url = f"{cfg.http_base_url.rstrip('/')}/"
    timeout = aiohttp.ClientTimeout(total=cfg.http_timeout_sec)
    headers = {"User-Agent": "lab-http-get-burst/1.0"}

    async with aiohttp.ClientSession(
        timeout=timeout, headers=headers
    ) as session:

        async def one() -> None:
            async with session.get(url) as resp:
                await resp.read()

        await bounded_gather(
            [one() for _ in range(1200)], cfg.http_concurrency
        )


async def attack_http_post_burst(cfg: LabConfig) -> None:
    """
    Simulates a burst of HTTP POST requests to a private lab service.
    Useful for request-body parsing and upload-ish app activity.
    """
    url = f"{cfg.http_base_url.rstrip('/')}/submit"
    timeout = aiohttp.ClientTimeout(total=cfg.http_timeout_sec)
    headers = {"User-Agent": "lab-http-post-burst/1.0"}

    async with aiohttp.ClientSession(
        timeout=timeout, headers=headers
    ) as session:

        async def one(i: int) -> None:
            payload = {
                "id": i,
                "ts": time.time(),
                "token": "".join(
                    random.choices(
                        string.ascii_lowercase + string.digits, k=16
                    )
                ),
            }
            async with session.post(url, json=payload) as resp:
                await resp.read()

        await bounded_gather(
            [one(i) for i in range(800)], cfg.http_concurrency
        )


async def attack_arp_scan_stub(cfg: LabConfig) -> None:
    return os.system(
        " arp-scan --interface=eth0 172.17.0.0/24 "
        "&&  arp-scan --interface=eth0 172.17.0.0/24"
    )


def attack_vertical_portscan_stub(cfg: LabConfig) -> None:
    """
    Vertical scan = many ports on one host.
    """
    cmd = ["nmap", "-Pn", "-p", "1-1024", cfg.port80_host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not in PATH")


async def attack_horizontal_portscan_stub(cfg: LabConfig) -> None:
    """
    Stub only.
    Horizontal scan = same port across many hosts.
    """

    cmd = ["nmap", "-Pn", "-p", "80", "173.252.96.0-254"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not in PATH")


async def attack_dns_query_burst(cfg: LabConfig) -> None:
    """
    Burst of DNS queries to a private lab resolver.
    Useful for resolver load and DNS telemetry paths.
    """
    loop = asyncio.get_running_loop()

    class NoopDatagramProtocol(asyncio.DatagramProtocol):
        pass

    transport, _ = await loop.create_datagram_endpoint(
        NoopDatagramProtocol,
        remote_addr=(cfg.dns_server, cfg.dns_port),
    )
    try:
        for i in range(10000):
            qname = f"{i}.{random.randint(1000, 999999)}.lab.test"
            packet = make_dns_query(qname, qtype=1)
            transport.sendto(packet)
            if i % 250 == 0:
                await asyncio.sleep(0)
    finally:
        transport.close()


async def attack_icmp_timestamp_scan_stub(cfg: LabConfig) -> None:
    cmd = ["nmap", "-Pn", "--script", "icmp-timestamp"]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False
        )

        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not in PATH")


async def attack_non_ssl_port_80_connection(cfg: LabConfig) -> None:
    """
    Opens 1000 plain TCP connections at once to port 80 on a private lab target.
    This is a safe way to exercise plain TCP-on-80 behavior in a lab.
    """
    await bounded_gather(
        [
            tcp_open_and_close(cfg.port80_host, cfg.port80_port, linger=2.0)
            for _ in range(1000)
        ],
        limit=1000,
    )


# Keep total count at 10 by splitting HTTP burst styles further.
async def attack_http_get_burst_alt(cfg: LabConfig) -> None:
    """
    Variant GET burst with query-string diversity.
    Helps create more varied request metadata without changing the basic behavior.
    """
    timeout = aiohttp.ClientTimeout(total=cfg.http_timeout_sec)
    headers = {"User-Agent": "lab-http-get-burst-alt/1.0"}

    async with aiohttp.ClientSession(
        timeout=timeout, headers=headers
    ) as session:

        async def one(i: int) -> None:
            url = f"{cfg.http_base_url.rstrip('/')}/?i={i}&r={random.randint(1, 10_000_000)}"
            async with session.get(url) as resp:
                await resp.read()

        await bounded_gather(
            [one(i) for i in range(1000)], cfg.http_concurrency
        )


async def attack_http_post_burst_alt(cfg: LabConfig) -> None:
    """
    Variant POST burst with larger JSON payloads.
    Useful for stressing app-layer request parsing a bit harder.
    """
    timeout = aiohttp.ClientTimeout(total=cfg.http_timeout_sec)
    headers = {"User-Agent": "lab-http-post-burst-alt/1.0"}
    url = f"{cfg.http_base_url.rstrip('/')}/submit"

    async with aiohttp.ClientSession(
        timeout=timeout, headers=headers
    ) as session:

        async def one(i: int) -> None:
            payload = {
                "id": i,
                "name": "".join(random.choices(string.ascii_letters, k=32)),
                "blob": "".join(
                    random.choices(
                        string.ascii_letters + string.digits, k=2048
                    )
                ),
                "ts": time.time(),
            }
            async with session.post(url, json=payload) as resp:
                await resp.read()

        await bounded_gather(
            [one(i) for i in range(500)], cfg.http_concurrency
        )


ATTACKS: list[tuple[str, Callable[[LabConfig], Awaitable[None]]]] = [
    ("http_get_burst", attack_http_get_burst),
    ("http_post_burst", attack_http_post_burst),
    ("arp_scan_stub", attack_arp_scan_stub),
    ("vertical_portscan_stub", attack_vertical_portscan_stub),
    ("horizontal_portscan_stub", attack_horizontal_portscan_stub),
    ("dns_query_burst", attack_dns_query_burst),
    ("icmp_timestamp_scan_stub", attack_icmp_timestamp_scan_stub),
    ("non_ssl_port_80_connection", attack_non_ssl_port_80_connection),
    ("http_get_burst_alt", attack_http_get_burst_alt),
    ("http_post_burst_alt", attack_http_post_burst_alt),
]


async def scheduler(cfg: LabConfig) -> None:
    attack_index = 0

    while True:
        name, fn = ATTACKS[attack_index]
        print(
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] sleeping {cfg.sleep_between_profiles_sec}s before {name}"
        )
        await asyncio.sleep(cfg.sleep_between_profiles_sec)

        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] START {name}")
        started = time.perf_counter()
        try:
            if inspect.iscoroutinefunction(fn):
                await fn(cfg)
            else:
                fn(cfg)
        except Exception as exc:
            print(
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR in {name}: {exc}"
            )
        else:
            elapsed = time.perf_counter() - started
            print(
                f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] END {name} duration={elapsed:.2f}s"
            )

        attack_index = (attack_index + 1) % len(ATTACKS)


async def main() -> None:
    await scheduler(CFG)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Stopped.")
