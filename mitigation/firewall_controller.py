#!/usr/bin/env python3
"""Temporary firewall mitigation controller for the isolated project lab."""

import argparse
import json
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

GATEWAY = "cp-gateway"
FAMILY = "inet"
TABLE = "mitigation"
CHAIN = "forward"

CLIENT_IP = "172.28.0.10"
SERVER_IP = "172.29.0.10"
SERVER_PORT = 8080
RULE_COMMENT = "temporary-lab-mitigation"
RATE_LIMIT_RULE_COMMENT = "temporary-lab-rate-limit"

LOG_FILE = Path(__file__).resolve().parent / "mitigation_actions.jsonl"

stop_event = threading.Event()
received_signal = None


def handle_signal(signum, _frame):
    """Request orderly shutdown; cleanup runs in main's finally block."""
    global received_signal
    received_signal = signal.Signals(signum).name
    stop_event.set()


def run_nft(*args):
    """Run nft inside the gateway and report useful errors."""
    result = subprocess.run(
        ["docker", "exec", GATEWAY, "nft", *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"nft {' '.join(args)} failed: {message}")
    return result.stdout


def log_event(event, **details):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **details,
    }
    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")
    print(json.dumps(record), flush=True)


def ensure_firewall_chain():
    """Create only our dedicated table and chain if missing."""
    tables = run_nft("list", "tables")
    if f"table {FAMILY} {TABLE}" not in tables:
        run_nft("add", "table", FAMILY, TABLE)

    chains = run_nft("list", "table", FAMILY, TABLE)
    if f"chain {CHAIN} " not in chains:
        run_nft(
            "add", "chain", FAMILY, TABLE, CHAIN,
            "{", "type", "filter", "hook", "forward",
            "priority", "filter", ";", "policy", "accept", ";", "}"
        )


def remove_our_rules():
    """Delete only rules bearing this controller's unique comment."""
    output = run_nft(
        "-a", "list", "chain", FAMILY, TABLE, CHAIN
    )
    handles = []
    for line in output.splitlines():
        if RULE_COMMENT in line and "handle " in line:
            handles.append(line.rsplit("handle ", 1)[1].strip())

    for handle in handles:
        run_nft(
            "delete", "rule", FAMILY, TABLE, CHAIN,
            "handle", handle
        )


def add_block():
    run_nft(
        "add", "rule", FAMILY, TABLE, CHAIN,
        "ip", "saddr", CLIENT_IP,
        "ip", "daddr", SERVER_IP,
        "tcp", "dport", str(SERVER_PORT),
        "counter", "drop",
        "comment", RULE_COMMENT
    )

def remove_rate_limit_rules():
    """Remove only this controller's temporary rate-limit rules."""
    output = run_nft(
        "-a", "list", "chain", FAMILY, TABLE, CHAIN
    )

    handles = []
    for line in output.splitlines():
        if RATE_LIMIT_RULE_COMMENT in line and "handle " in line:
            handles.append(line.rsplit("handle ", 1)[1].strip())

    for handle in handles:
        run_nft(
            "delete", "rule", FAMILY, TABLE, CHAIN,
            "handle", handle
        )


def add_rate_limit(rate=20, burst=40):
    run_nft(
        "add", "rule", FAMILY, TABLE, CHAIN,
        "ip", "saddr", CLIENT_IP,
        "ip", "daddr", SERVER_IP,
        "tcp", "dport", str(SERVER_PORT),
        "limit", "rate", "over", f"{rate}/second",
        "burst", f"{burst}", "packets",
        "counter", "drop",
        "comment", RATE_LIMIT_RULE_COMMENT
    )


def apply_temporary_rate_limit(duration=30, rate=20, burst=40):
    if not 1 <= duration <= 60:
        raise ValueError("Duration must be between 1 and 60 seconds.")

    applied = False

    try:
        ensure_firewall_chain()
        remove_rate_limit_rules()
        add_rate_limit(rate, burst)
        applied = True

        log_event(
            "rate_limit_applied",
            client=CLIENT_IP,
            server=SERVER_IP,
            port=SERVER_PORT,
            rate_per_second=rate,
            burst_packets=burst,
            duration_seconds=duration,
        )

        time.sleep(duration)

        return {
            "success": True,
            "action": "RATE_LIMIT",
            "rate_per_second": rate,
            "burst_packets": burst,
            "duration_seconds": duration,
        }

    finally:
        if applied:
            remove_rate_limit_rules()
            log_event("rate_limit_removed")


def apply_temporary_block(duration=15):
    if not 1 <= duration <= 60:
        raise ValueError("Duration must be between 1 and 60 seconds.")

    applied = False

    try:
        ensure_firewall_chain()
        remove_our_rules()
        add_block()
        applied = True

        log_event(
            "block_applied",
            client=CLIENT_IP,
            server=SERVER_IP,
            port=SERVER_PORT,
            duration_seconds=duration,
        )

        time.sleep(duration)

        return {
            "success": True,
            "action": "BLOCK",
            "client": CLIENT_IP,
            "server": SERVER_IP,
            "port": SERVER_PORT,
            "duration_seconds": duration,
        }

    finally:
        if applied:
            remove_our_rules()
            log_event("block_removed")

def main():
    parser = argparse.ArgumentParser(
        description="Apply a temporary, allowlisted lab firewall block."
    )
    parser.add_argument("--duration", type=int, default=15)
    args = parser.parse_args()

    if not 1 <= args.duration <= 60:
        parser.error("Duration must be between 1 and 60 seconds.")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    applied = False

    try:
        ensure_firewall_chain()
        # Remove stale rules from an earlier interrupted run.
        remove_our_rules()

        add_block()
        applied = True

        log_event(
            "block_applied",
            client=CLIENT_IP,
            server=SERVER_IP,
            port=SERVER_PORT,
            duration_seconds=args.duration,
        )
        print(f"Block active for up to {args.duration} seconds.", flush=True)

        # Returns early when SIGINT or SIGTERM requests shutdown.
        was_interrupted = stop_event.wait(args.duration)
        if was_interrupted:
            log_event("controller_interrupted", signal=received_signal)

    except Exception as exc:
        log_event("controller_error", error=str(exc))
        raise

    finally:
        if applied:
            try:
                remove_our_rules()
                log_event("block_removed")
            except Exception as exc:
                log_event("cleanup_error", error=str(exc))
                raise


if __name__ == "__main__":
    main()
