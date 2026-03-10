#!/usr/bin/env python3
"""
Mixed traffic generator for soak testing.

Features
--------
• Precise flow rate control
• Bounded concurrency
• HTTP, DNS, ICMP, TCP traffic mix
• Response reading for realistic flows
• Safe for long soak tests (no task explosion)

Example target:
    Soft break: 1000 FPS
    Soak load: 70% → 700 FPS
"""

import asyncio
import random
import socket
import string
import struct
import time
import aiohttp


TARGET = "127.0.0.1"
HTTP_PORT = 8080
DNS_SERVER = ("8.8.8.8", 53)

SOFT_BREAK_FPS = 1000
TARGET_FPS = int(SOFT_BREAK_FPS * 0.7)

HTTP_RATIO = 0.4
DNS_RATIO = 0.2
PING_RATIO = 0.2
TCP_RATIO = 0.2

MAX_CONCURRENCY = 300


running_flows = 0
counter_lock = asyncio.Lock()
sem = asyncio.Semaphore(MAX_CONCURRENCY)


def rand_path():
    s = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"/{s}"


async def inc_counter():
    global running_flows
    async with counter_lock:
        running_flows += 1


# -----------------------------
# HTTP
# -----------------------------


async def http_get(session):
    try:
        async with session.get(
            f"http://{TARGET}:{HTTP_PORT}{rand_path()}"
        ) as resp:
            await resp.read()
    except Exception:
        pass

    await inc_counter()


async def http_post(session):
    try:
        async with session.post(
            f"http://{TARGET}:{HTTP_PORT}/login",
            data={"user": rand_path(), "pass": rand_path()},
        ) as resp:
            await resp.read()
    except Exception:
        pass

    await inc_counter()


# -----------------------------
# DNS
# -----------------------------


async def dns_query():
    try:
        qname = rand_path().strip("/") + ".example.com"

        tid = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)

        q = b"".join(
            len(p).to_bytes(1, "big") + p.encode() for p in qname.split(".")
        )
        q += b"\x00"

        question = q + struct.pack(">HH", 1, 1)
        msg = header + question

        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=DNS_SERVER,
        )

        transport.sendto(msg)

        await asyncio.sleep(0.05)

        transport.close()

    except Exception:
        pass

    await inc_counter()


# -----------------------------
# ICMP
# -----------------------------


def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        part = data[i] << 8
        if i + 1 < len(data):
            part += data[i + 1]
        s += part

    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


async def icmp_ping():
    try:
        loop = asyncio.get_running_loop()

        sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        sock.setblocking(False)

        pid = random.randint(0, 65535)
        seq = 1

        header = struct.pack(">BBHHH", 8, 0, 0, pid, seq)
        payload = b"soaktest"

        cs = checksum(header + payload)
        header = struct.pack(">BBHHH", 8, 0, cs, pid, seq)

        packet = header + payload

        await loop.sock_sendto(sock, packet, (DNS_SERVER[0], 0))

        sock.close()

    except Exception:
        pass

    await inc_counter()


# -----------------------------
# TCP
# -----------------------------


async def tcp_connect():
    try:
        reader, writer = await asyncio.open_connection(TARGET, HTTP_PORT)

        writer.write(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        await writer.drain()

        await reader.read(1024)

        writer.close()
        await writer.wait_closed()

    except Exception:
        pass

    await inc_counter()


# -----------------------------
# Flow dispatcher
# -----------------------------


async def do_flow(session):
    async with sem:

        r = random.random()

        if r < HTTP_RATIO:
            if random.random() < 0.5:
                await http_get(session)
            else:
                await http_post(session)

        elif r < HTTP_RATIO + DNS_RATIO:
            await dns_query()

        elif r < HTTP_RATIO + DNS_RATIO + PING_RATIO:
            await icmp_ping()

        else:
            await tcp_connect()


# -----------------------------
# Rate controller
# -----------------------------


async def controller():

    interval = 1 / TARGET_FPS

    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENCY)

    async with aiohttp.ClientSession(connector=connector) as session:

        while True:

            start = time.perf_counter()

            asyncio.create_task(do_flow(session))

            elapsed = time.perf_counter() - start

            sleep = interval - elapsed
            if sleep > 0:
                await asyncio.sleep(sleep)


# -----------------------------
# Metrics
# -----------------------------


async def metrics():

    global running_flows

    while True:
        await asyncio.sleep(1)

        async with counter_lock:
            fps = running_flows
            running_flows = 0

        print("flows/sec:", fps)


# -----------------------------
# Main
# -----------------------------


async def main():

    await asyncio.gather(
        controller(),
        metrics(),
    )


if __name__ == "__main__":
    asyncio.run(main())
