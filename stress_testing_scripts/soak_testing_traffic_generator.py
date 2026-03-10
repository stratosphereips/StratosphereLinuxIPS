#!/usr/bin/env python3
"""Generate mixed traffic flows for soak testing."""
import asyncio
import random
import string
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

running_flows = 0


def rand_path():
    """Return a short random path segment."""
    s = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"/{s}"


async def http_get(session):
    """Issue a single HTTP GET request."""
    global running_flows
    try:
        async with session.get(f"http://{TARGET}:{HTTP_PORT}{rand_path()}"):
            pass
    except Exception:
        pass
    running_flows += 1


async def http_post(session):
    """Issue a single HTTP POST request."""
    global running_flows
    try:
        async with session.post(
            f"http://{TARGET}:{HTTP_PORT}/login",
            data={"user": rand_path(), "pass": rand_path()},
        ):
            pass
    except Exception:
        pass
    running_flows += 1


async def dns_query():
    """Perform a DNS lookup for a random hostname."""
    global running_flows
    try:
        loop = asyncio.get_running_loop()
        await loop.getaddrinfo(f"{rand_path()}.example.com", None)
    except Exception:
        pass
    running_flows += 1


async def ping():
    """Send a single ICMP ping to the DNS server."""
    global running_flows
    proc = await asyncio.create_subprocess_exec(
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        DNS_SERVER[0],
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()
    running_flows += 1


async def tcp_connect():
    """Open a TCP connection and send a minimal HTTP request."""
    global running_flows
    try:
        reader, writer = await asyncio.open_connection(TARGET, HTTP_PORT)
        writer.write(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    running_flows += 1


async def worker(session):
    """Dispatch a single randomized traffic action."""
    r = random.random()

    if r < HTTP_RATIO:
        if random.random() < 0.5:
            await http_get(session)
        else:
            await http_post(session)

    elif r < HTTP_RATIO + DNS_RATIO:
        await dns_query()

    elif r < HTTP_RATIO + DNS_RATIO + PING_RATIO:
        await ping()

    else:
        await tcp_connect()


async def controller():
    """Run the traffic generator at the target flows per second."""
    global running_flows

    async with aiohttp.ClientSession() as session:

        while True:

            start = time.time()
            running_flows = 0

            tasks = []

            while running_flows < TARGET_FPS:
                tasks.append(asyncio.create_task(worker(session)))

            await asyncio.gather(*tasks)

            elapsed = time.time() - start

            if elapsed < 1:
                await asyncio.sleep(1 - elapsed)

            print(f"flows/sec: {running_flows}")


if __name__ == "__main__":
    asyncio.run(controller())
