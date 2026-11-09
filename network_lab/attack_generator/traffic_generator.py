"""
StealthGuard - Unified Traffic Generator

Generates controlled, protocol-appropriate traffic for all 15 DDoS
attack classes inside the isolated Docker lab.

Traffic is sent from cp-client (172.28.0.10) through cp-gateway
to cp-protected-server (172.29.0.10) or to non-existent reflector IPs.

Each attack class produces flow characteristics designed to match the
CIC-DDoS2019 training distribution that the frozen model expects.

Usage (from inside cp-client):
    python traffic_generator.py --class Syn --count 100
    python traffic_generator.py --class DrDoS_NTP --count 100
    python traffic_generator.py --list
"""

import argparse
import random
import sys
import time
from ipaddress import ip_address

from scapy.all import IP, TCP, UDP, Raw, send

# ---------------------------------------------------------------------------
# Lab topology
# ---------------------------------------------------------------------------

CLIENT_NETWORK = "172.28.0"
SERVER_IP = "172.29.0.10"
GATEWAY_CLIENT_IP = "172.28.0.2"

# Source IPs used to simulate multiple attackers (172.28.0.11 - 172.28.0.30)
SOURCE_IPS = [f"172.28.0.{i}" for i in range(11, 31)]

# ---------------------------------------------------------------------------
# Attack class configurations
#
# Each entry defines how to generate traffic for one class. The goal is to
# produce flow-level features (packet sizes, rates, durations, fwd/bwd
# ratios) that fall within the range the trained model associates with
# that class.
# ---------------------------------------------------------------------------

ATTACK_CLASSES = {
    "Syn": {
        "protocol": "tcp",
        "dst_port": 8080,
        "flags": "S",
        "payload_size": 0,
        "inter_packet_delay": 0.005,
        "description": "TCP SYN flood - SYN only, no completion, small packets",
    },
    "UDP": {
        "protocol": "udp",
        "dst_port": None,  # random port
        "dst_port_range": (1024, 65535),
        "payload_size": (64, 512),
        "inter_packet_delay": 0.01,
        "description": "UDP flood - random ports, variable payload sizes",
    },
    "UDP-lag": {
        "protocol": "udp",
        "dst_port": None,
        "dst_port_range": (1024, 65535),
        "payload_size": (32, 128),
        "inter_packet_delay": 0.5,
        "description": "Low-rate UDP - delays between packets, longer duration",
    },
    "TFTP": {
        "protocol": "udp",
        "dst_port": 69,
        "payload_size": (40, 60),
        "inter_packet_delay": 0.05,
        "description": "TFTP read/write requests - small UDP packets on port 69",
    },
    "Portmap": {
        "protocol": "tcp",
        "dst_port": 111,
        "payload_size": (64, 256),
        "inter_packet_delay": 0.02,
        "description": "Portmap/RPC - TCP port 111",
    },
    "MSSQL": {
        "protocol": "tcp",
        "dst_port": 1433,
        "payload_size": (128, 512),
        "inter_packet_delay": 0.03,
        "description": "MSSQL - TCP port 1433, TDS-like packets",
    },
    "NetBIOS": {
        "protocol": "udp",
        "dst_port": 137,
        "payload_size": (48, 96),
        "inter_packet_delay": 0.03,
        "description": "NetBIOS name service - UDP port 137",
    },
    "DrDoS_DNS": {
        "protocol": "udp",
        "dst_port": 53,
        "payload_size": (40, 80),
        "inter_packet_delay": 0.01,
        "description": "DrDoS DNS - UDP port 53, small queries",
    },
    "DrDoS_NTP": {
        "protocol": "udp",
        "dst_port": 123,
        "payload_size": (72, 120),
        "inter_packet_delay": 0.02,
        "description": "DrDoS NTP - UDP port 123, monlist-style requests",
    },
    "DrDoS_SSDP": {
        "protocol": "udp",
        "dst_port": 1900,
        "payload_size": (300, 500),
        "inter_packet_delay": 0.03,
        "description": "DrDoS SSDP - UDP port 1900, M-SEARCH requests",
    },
    "DrDoS_SNMP": {
        "protocol": "udp",
        "dst_port": 161,
        "payload_size": (64, 128),
        "inter_packet_delay": 0.02,
        "description": "DrDoS SNMP - UDP port 161, GET requests",
    },
    "DrDoS_LDAP": {
        "protocol": "udp",
        "dst_port": 389,
        "payload_size": (100, 300),
        "inter_packet_delay": 0.03,
        "description": "DrDoS LDAP - UDP port 389, search requests",
    },
    "DrDoS_MSSQL": {
        "protocol": "udp",
        "dst_port": 1433,
        "payload_size": (128, 512),
        "inter_packet_delay": 0.03,
        "description": "DrDoS MSSQL - UDP port 1433",
    },
    "DrDoS_NetBIOS": {
        "protocol": "udp",
        "dst_port": 137,
        "payload_size": (48, 96),
        "inter_packet_delay": 0.03,
        "description": "DrDoS NetBIOS - UDP port 137",
    },
    "DrDoS_UDP": {
        "protocol": "udp",
        "dst_port": None,
        "dst_port_range": (1024, 65535),
        "payload_size": (200, 1000),
        "inter_packet_delay": 0.005,
        "description": "DrDoS UDP - UDP flood, random ports, larger payloads",
    },
}

# ---------------------------------------------------------------------------
# Traffic generation
# ---------------------------------------------------------------------------


def _random_payload(min_size: int, max_size: int) -> bytes:
    """Generate a random payload of the given size range."""
    size = random.randint(min_size, max_size)
    return bytes(random.randint(0, 255) for _ in range(size))


def _build_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    payload: bytes,
    flags: str | None = None,
):
    """Build a single Scapy packet."""
    ip = IP(src=src_ip, dst=dst_ip)

    if protocol == "tcp":
        tcp_flags = flags if flags else "S"
        return ip / TCP(sport=src_port, dport=dst_port, flags=tcp_flags) / Raw(
            load=payload
        )
    else:
        return ip / UDP(sport=src_port, dport=dst_port) / Raw(load=payload)


def generate_traffic(
    attack_class: str,
    count: int,
    rate: float = 10.0,
    dst_ip: str = SERVER_IP,
):
    """
    Generate *count* packets for *attack_class*.

    Parameters
    ----------
    attack_class : str
        One of the keys in ATTACK_CLASSES.
    count : int
        Number of packets to send.
    rate : float
        Packets per second (overall rate limit).
    dst_ip : str
        Destination IP address.
    """
    if attack_class not in ATTACK_CLASSES:
        print(f"Unknown attack class: {attack_class}")
        print(f"Available classes: {', '.join(sorted(ATTACK_CLASSES))}")
        sys.exit(1)

    config = ATTACK_CLASSES[attack_class]
    protocol = config["protocol"]
    payload_min, payload_max = config["payload_size"]
    delay = config["inter_packet_delay"]

    print(f"Generating {attack_class} traffic")
    print(f"  Protocol: {protocol.upper()}")
    print(f"  Packets: {count}")
    print(f"  Target: {dst_ip}")
    print(f"  Payload size: {payload_min}-{payload_max} bytes")
    print(f"  Inter-packet delay: {delay}s")
    print()

    sent = 0
    for i in range(count):
        src_ip = random.choice(SOURCE_IPS)
        src_port = random.randint(40000, 60000)

        if config["dst_port"] is not None:
            dst_port = config["dst_port"]
        else:
            lo, hi = config["dst_port_range"]
            dst_port = random.randint(lo, hi)

        payload = _random_payload(payload_min, payload_max)

        pkt = _build_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            payload=payload,
            flags=config.get("flags"),
        )

        send(pkt, verbose=False)
        sent += 1

        if sent % 10 == 0:
            print(f"  Sent {sent}/{count} packets", end="\r")

        # Rate limiting: sleep based on configured inter-packet delay
        if delay > 0:
            time.sleep(delay)

    print(f"\n  Sent {sent}/{count} packets for {attack_class}")


def list_classes():
    """Print all available attack classes with descriptions."""
    print("Available attack classes:")
    print("-" * 70)
    for name, config in sorted(ATTACK_CLASSES.items()):
        proto = config["protocol"].upper()
        port = config["dst_port"] or "random"
        print(f"  {name:20} {proto:4} port={port}  {config['description']}")
    print("-" * 70)
    print(f"Total: {len(ATTACK_CLASSES)} classes")


def main():
    parser = argparse.ArgumentParser(
        description="StealthGuard traffic generator for DDoS attack classes"
    )
    parser.add_argument(
        "--class",
        dest="attack_class",
        help="Attack class to generate (use --list to see options)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available attack classes",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of packets to generate (default: 100)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=10.0,
        help="Packets per second (default: 10.0)",
    )
    parser.add_argument(
        "--dst",
        default=SERVER_IP,
        help=f"Destination IP (default: {SERVER_IP})",
    )

    args = parser.parse_args()

    if args.list:
        list_classes()
        return

    if not args.attack_class:
        parser.error("--class is required (use --list to see options)")

    if not (1 <= args.count <= 10000):
        parser.error("--count must be between 1 and 10000")

    generate_traffic(
        attack_class=args.attack_class,
        count=args.count,
        rate=args.rate,
        dst_ip=args.dst,
    )


if __name__ == "__main__":
    main()
