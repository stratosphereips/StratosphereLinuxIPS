"""Generate benign and malicious traffic for exercising Slips detections."""

import argparse
import ipaddress
import os
import random
import socket
import string
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    Ether,
    ICMP,
    IP,
    TCP,
    UDP,
    conf,
    get_if_hwaddr,
    send,
    sendp,
)


DETECTION_NOTES = {
    "ARP_SCAN": "ARP requests to at least 5 different IPs within 30 seconds.",
    "ARP_OUTSIDE_LOCALNET": "ARP request for a private IP outside the local network.",
    "UNSOLICITED_ARP": "Broadcast ARP reply with non-zero sender hardware address.",
    "HORIZONTAL_PORT_SCAN": "TCP SYNs to one port across more than 5 destination IPs.",
    "VERTICAL_PORT_SCAN": "TCP SYNs to more than 5 ports on one destination IP.",
    "DNS_ARPA_SCAN": "At least 10 unique in-addr.arpa DNS queries within 2 seconds.",
    "DGA_NXDOMAINS": "Batches of random domains expected to return NXDOMAIN.",
    "UNKNOWN_PORT": "Connection attempts to ports absent from Slips service data.",
    "PORT_0_CONNECTION": "TCP packet with source or destination port 0.",
    "CONNECTION_TO_PRIVATE_IP": "Connection from a private IP to another private IP.",
    "DIFFERENT_LOCALNET": "Connection or ARP to a private IP outside the local network.",
    "ICMP_TIMESTAMP_SCAN": "ICMP timestamp probes to many hosts.",
    "ICMP_ADDRESS_SCAN": "ICMP address-mask probes to many hosts.",
    "MULTIPLE_RECONNECTION_ATTEMPTS": "Repeated rejected connections if the target sends RSTs.",
}


@dataclass(frozen=True)
class GeneratorConfig:
    """Configuration for traffic generation.

    Parameters:
    interface: Network interface used for packet injection.
    source_ip: IPv4 address to use in ARP sender fields.
    local_network: Local IPv4 network inferred from the interface.
    dns_server: DNS resolver to receive generated DNS queries.
    interval: Delay between generated traffic bursts.
    malicious_rate: Probability of selecting a malicious burst.
    verbose: Whether to print each generated burst.
    """

    interface: str
    source_ip: str
    local_network: ipaddress.IPv4Network
    dns_server: str
    interval: float
    malicious_rate: float
    verbose: bool


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Return:
    argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Generate continuous benign and malicious traffic that exercises "
            "Slips detections. Stop with Ctrl+C."
        )
    )
    parser.add_argument(
        "-i",
        "--interface",
        default=str(conf.iface),
        help="interface to use for raw packet generation",
    )
    parser.add_argument(
        "--source-ip",
        default="",
        help="source IPv4 address for ARP sender fields; default is inferred",
    )
    parser.add_argument(
        "--dns-server",
        default="",
        help="DNS server for DNS bursts; default is gateway or 1.1.1.1",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds to sleep between bursts",
    )
    parser.add_argument(
        "--malicious-rate",
        type=float,
        default=0.75,
        help="probability from 0.0 to 1.0 of generating malicious bursts",
    )
    parser.add_argument(
        "--list-detections",
        action="store_true",
        help="print targeted Slips detections and exit",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="print only periodic counters",
    )
    return parser.parse_args()


def require_root() -> None:
    """Ensure raw packet generation has enough privileges."""
    if os.geteuid() != 0:
        raise SystemExit(
            "traffic_generator.py must run as root for raw packets."
        )


def run_command(command: list[str]) -> str:
    """Run a command and return its standard output.

    Parameters:
    command: Command and arguments to execute.

    Return:
    str: Command output, or an empty string on failure.
    """
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return completed.stdout.strip()


def infer_interface_network(
    interface: str,
) -> tuple[str, ipaddress.IPv4Network]:
    """Infer the primary IPv4 address and network for an interface.

    Parameters:
    interface: Interface name to inspect.

    Return:
    tuple[str, ipaddress.IPv4Network]: Interface IPv4 address and network.
    """
    output = run_command(["ip", "-o", "-4", "addr", "show", "dev", interface])
    for line in output.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        cidr = parts[parts.index("inet") + 1]
        address = ipaddress.IPv4Interface(cidr)
        return str(address.ip), address.network

    fallback = ipaddress.IPv4Interface("192.168.56.10/24")
    return str(fallback.ip), fallback.network


def infer_default_gateway() -> str:
    """Infer the default IPv4 gateway.

    Return:
    str: Gateway IP address, or 1.1.1.1 if it cannot be inferred.
    """
    output = run_command(["ip", "route", "show", "default"])
    parts = output.split()
    if "via" in parts:
        return parts[parts.index("via") + 1]
    return "1.1.1.1"


def build_config(args: argparse.Namespace) -> GeneratorConfig:
    """Build generator configuration from arguments and interface data.

    Parameters:
    args: Parsed command-line arguments.

    Return:
    GeneratorConfig: Runtime generator configuration.
    """
    source_ip, local_network = infer_interface_network(args.interface)
    if args.source_ip:
        source_ip = args.source_ip

    malicious_rate = min(1.0, max(0.0, args.malicious_rate))
    dns_server = args.dns_server or infer_default_gateway()
    return GeneratorConfig(
        interface=args.interface,
        source_ip=source_ip,
        local_network=local_network,
        dns_server=dns_server,
        interval=max(0.0, args.interval),
        malicious_rate=malicious_rate,
        verbose=not args.quiet,
    )


def print_targeted_detections() -> None:
    """Print detections targeted by this generator."""
    for name, reason in DETECTION_NOTES.items():
        print(f"{name}: {reason}")


def random_label(length: int = 12) -> str:
    """Generate a random lowercase DNS label.

    Parameters:
    length: Number of characters in the label.

    Return:
    str: Random DNS-safe label.
    """
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def random_mac() -> str:
    """Generate a locally administered unicast MAC address.

    Return:
    str: Random MAC address.
    """
    octets = [0x02, *[random.randint(0x00, 0xFF) for _ in range(5)]]
    return ":".join(f"{octet:02x}" for octet in octets)


def local_hosts(network: ipaddress.IPv4Network, count: int) -> list[str]:
    """Return candidate local hosts for ARP traffic.

    Parameters:
    network: Local IPv4 network.
    count: Number of hosts requested.

    Return:
    list[str]: Host IP addresses in the network.
    """
    hosts = [str(host) for host in network.hosts()]
    if len(hosts) >= count:
        return random.sample(hosts, count)

    base = int(ipaddress.IPv4Address("192.168.56.1"))
    return [
        str(ipaddress.IPv4Address(base + offset)) for offset in range(count)
    ]


def documentation_ips(count: int) -> list[str]:
    """Return TEST-NET destination IPs for safe scan-like packets.

    Parameters:
    count: Number of IPs requested.

    Return:
    list[str]: Documentation-range IP addresses.
    """
    networks = [
        ipaddress.IPv4Network("192.0.2.0/24"),
        ipaddress.IPv4Network("198.51.100.0/24"),
        ipaddress.IPv4Network("203.0.113.0/24"),
    ]
    results: list[str] = []
    while len(results) < count:
        network = random.choice(networks)
        host = random.randint(1, network.num_addresses - 2)
        results.append(str(network.network_address + host))
    return results


def outside_private_ip(local_network: ipaddress.IPv4Network) -> str:
    """Return a private IP outside the local network.

    Parameters:
    local_network: Local IPv4 network to avoid.

    Return:
    str: Private IPv4 address outside the local network.
    """
    candidates = [
        ipaddress.IPv4Address("10.254.254.10"),
        ipaddress.IPv4Address("172.31.254.10"),
        ipaddress.IPv4Address("192.168.254.10"),
    ]
    for candidate in candidates:
        if candidate not in local_network:
            return str(candidate)
    return "10.253.253.10"


def send_l3(packet: IP, count: int = 1) -> None:
    """Send a layer-3 packet quietly.

    Parameters:
    packet: Scapy IP packet to send.
    count: Number of times to send the packet.
    """
    send(packet, count=count, verbose=False)


def send_l2(packet: Ether, interface: str, count: int = 1) -> None:
    """Send a layer-2 packet quietly.

    Parameters:
    packet: Scapy Ethernet packet to send.
    interface: Interface used for transmission.
    count: Number of times to send the packet.
    """
    sendp(packet, iface=interface, count=count, verbose=False)


def burst_arp_scan(config: GeneratorConfig) -> str:
    """Generate ARP scan traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    source_mac = get_if_hwaddr(config.interface)
    for target in local_hosts(config.local_network, 7):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=source_mac) / ARP(
            op="who-has",
            hwsrc=source_mac,
            psrc=config.source_ip,
            hwdst="00:00:00:00:00:00",
            pdst=target,
        )
        send_l2(packet, config.interface)
        time.sleep(0.05)
    return "ARP_SCAN"


def burst_arp_outside_localnet(config: GeneratorConfig) -> str:
    """Generate ARP traffic to a private IP outside the local network.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    source_mac = get_if_hwaddr(config.interface)
    target = outside_private_ip(config.local_network)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=source_mac) / ARP(
        op="who-has",
        hwsrc=source_mac,
        psrc=config.source_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target,
    )
    send_l2(packet, config.interface)
    return "ARP_OUTSIDE_LOCALNET"


def burst_unsolicited_arp(config: GeneratorConfig) -> str:
    """Generate an unsolicited broadcast ARP reply.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    source_mac = get_if_hwaddr(config.interface)
    announced_ip = random.choice(local_hosts(config.local_network, 10))
    packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=source_mac) / ARP(
        op="is-at",
        hwsrc=source_mac,
        psrc=announced_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=announced_ip,
    )
    send_l2(packet, config.interface)
    return "UNSOLICITED_ARP"


def burst_horizontal_portscan(config: GeneratorConfig) -> str:
    """Generate horizontal TCP portscan traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    dport = random.choice([23, 2323, 3389, 5432, 65000])
    for target in documentation_ips(8):
        packet = IP(dst=target) / TCP(
            sport=random.randint(20000, 60999),
            dport=dport,
            flags="S",
            seq=random.randint(1, 1000000),
        )
        send_l3(packet)
    return "HORIZONTAL_PORT_SCAN"


def burst_vertical_portscan(config: GeneratorConfig) -> str:
    """Generate vertical TCP portscan traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    target = random.choice(documentation_ips(1))
    for dport in random.sample(range(20000, 65100), 10):
        packet = IP(dst=target) / TCP(
            sport=random.randint(20000, 60999),
            dport=dport,
            flags="S",
            seq=random.randint(1, 1000000),
        )
        send_l3(packet)
    return "VERTICAL_PORT_SCAN"


def burst_dns_arpa_scan(config: GeneratorConfig) -> str:
    """Generate reverse-DNS scan traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    for offset in range(10):
        query = f"{offset}.{random.randint(1, 254)}.51.198.in-addr.arpa"
        packet = (
            IP(dst=config.dns_server)
            / UDP(
                sport=random.randint(20000, 60999),
                dport=53,
            )
            / DNS(rd=1, qd=DNSQR(qname=query, qtype="PTR"))
        )
        send_l3(packet)
    return "DNS_ARPA_SCAN"


def burst_dga_nxdomains(config: GeneratorConfig) -> str:
    """Generate random DNS queries expected to return NXDOMAIN.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    for _ in range(12):
        query = f"{random_label(18)}.{random_label(10)}.invalid"
        packet = (
            IP(dst=config.dns_server)
            / UDP(
                sport=random.randint(20000, 60999),
                dport=53,
            )
            / DNS(rd=1, qd=DNSQR(qname=query, qtype="A"))
        )
        send_l3(packet)
    return "DGA_NXDOMAINS"


def burst_unknown_port(config: GeneratorConfig) -> str:
    """Generate traffic to an uncommon destination port.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    target = random.choice(documentation_ips(1))
    packet = IP(dst=target) / UDP(
        sport=random.randint(20000, 60999),
        dport=random.randint(49152, 65535),
    )
    send_l3(packet)
    return "UNKNOWN_PORT"


def burst_port_zero(config: GeneratorConfig) -> str:
    """Generate a TCP packet involving port 0.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    target = random.choice(documentation_ips(1))
    packet = IP(dst=target) / TCP(
        sport=random.choice([0, random.randint(20000, 60999)]),
        dport=random.choice([0, 80]),
        flags="S",
    )
    send_l3(packet)
    return "PORT_0_CONNECTION"


def burst_private_ip_connection(config: GeneratorConfig) -> str:
    """Generate private-IP connection traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    target = outside_private_ip(config.local_network)
    packet = IP(dst=target) / TCP(
        sport=random.randint(20000, 60999),
        dport=random.choice([445, 8080, 5900]),
        flags="S",
    )
    send_l3(packet)
    return "CONNECTION_TO_PRIVATE_IP / DIFFERENT_LOCALNET"


def burst_icmp_timestamp_scan(config: GeneratorConfig) -> str:
    """Generate ICMP timestamp scan traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    for target in documentation_ips(30):
        send_l3(IP(dst=target) / ICMP(type=13))
    return "ICMP_TIMESTAMP_SCAN"


def burst_icmp_address_scan(config: GeneratorConfig) -> str:
    """Generate ICMP address-mask scan traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    for target in documentation_ips(30):
        send_l3(IP(dst=target) / ICMP(type=17))
    return "ICMP_ADDRESS_SCAN"


def burst_reconnection_attempts(config: GeneratorConfig) -> str:
    """Generate repeated connection attempts that may be rejected.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Targeted detection name.
    """
    target = infer_default_gateway()
    for _ in range(6):
        packet = IP(dst=target) / TCP(
            sport=random.randint(20000, 60999),
            dport=1,
            flags="S",
            seq=random.randint(1, 1000000),
        )
        send_l3(packet)
    return "MULTIPLE_RECONNECTION_ATTEMPTS"


def burst_benign_dns(config: GeneratorConfig) -> str:
    """Generate benign DNS query traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Traffic type name.
    """
    query = random.choice(
        ["example.com", "iana.org", "wikipedia.org", "stratosphereips.org"]
    )
    packet = (
        IP(dst=config.dns_server)
        / UDP(
            sport=random.randint(20000, 60999),
            dport=53,
        )
        / DNS(rd=1, qd=DNSQR(qname=query, qtype="A"))
    )
    send_l3(packet)
    return "BENIGN_DNS"


def burst_benign_ping(config: GeneratorConfig) -> str:
    """Generate benign ICMP echo traffic.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Traffic type name.
    """
    target = infer_default_gateway()
    send_l3(IP(dst=target) / ICMP(type=8))
    return "BENIGN_PING"


def burst_benign_tcp(config: GeneratorConfig) -> str:
    """Generate a short benign TCP connection attempt.

    Parameters:
    config: Runtime generator configuration.

    Return:
    str: Traffic type name.
    """
    target = random.choice(["93.184.216.34", "1.1.1.1"])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect((target, 80))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        except OSError:
            pass
    return "BENIGN_TCP"


def choose_burst(
    malicious_bursts: Iterable[Callable[[GeneratorConfig], str]],
    benign_bursts: Iterable[Callable[[GeneratorConfig], str]],
    malicious_rate: float,
) -> Callable[[GeneratorConfig], str]:
    """Choose the next burst function.

    Parameters:
    malicious_bursts: Malicious traffic burst functions.
    benign_bursts: Benign traffic burst functions.
    malicious_rate: Probability of selecting malicious traffic.

    Return:
    Callable[[GeneratorConfig], str]: Selected burst function.
    """
    if random.random() < malicious_rate:
        return random.choice(list(malicious_bursts))
    return random.choice(list(benign_bursts))


def run_forever(config: GeneratorConfig) -> None:
    """Generate traffic until interrupted.

    Parameters:
    config: Runtime generator configuration.
    """
    malicious_bursts = (
        burst_arp_scan,
        burst_arp_outside_localnet,
        burst_unsolicited_arp,
        burst_horizontal_portscan,
        burst_vertical_portscan,
        burst_dns_arpa_scan,
        burst_dga_nxdomains,
        burst_unknown_port,
        burst_port_zero,
        burst_private_ip_connection,
        burst_icmp_timestamp_scan,
        burst_icmp_address_scan,
        burst_reconnection_attempts,
    )
    benign_bursts = (
        burst_benign_dns,
        burst_benign_ping,
        burst_benign_tcp,
    )
    counters: dict[str, int] = {}
    started = time.time()

    print(
        "Generating traffic on "
        f"{config.interface} ({config.source_ip}, {config.local_network})."
    )
    print("Stop with Ctrl+C.")

    while True:
        burst = choose_burst(
            malicious_bursts,
            benign_bursts,
            config.malicious_rate,
        )
        name = burst(config)
        counters[name] = counters.get(name, 0) + 1

        if config.verbose:
            print(f"{time.strftime('%H:%M:%S')} generated {name}")
        elif int(time.time() - started) % 30 == 0:
            print_counters(counters)

        time.sleep(config.interval)


def print_counters(counters: dict[str, int]) -> None:
    """Print generated traffic counters.

    Parameters:
    counters: Mapping of traffic names to generated burst counts.
    """
    summary = ", ".join(
        f"{name}={count}" for name, count in sorted(counters.items())
    )
    print(f"Generated counters: {summary}")


def main() -> None:
    """Run the traffic generator command-line entry point."""
    args = parse_args()
    if args.list_detections:
        print_targeted_detections()
        return

    require_root()
    config = build_config(args)
    try:
        run_forever(config)
    except KeyboardInterrupt:
        print("\nStopped traffic generation.")


if __name__ == "__main__":
    main()
