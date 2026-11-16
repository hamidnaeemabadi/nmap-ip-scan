#!/usr/bin/env python3
"""Inventory IPv4 hosts with TCP connect probes and reverse DNS; never ping."""

import argparse
import csv
import errno
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor


FIELDS = ("ip", "status", "reverse_dns", "tcp_open", "tcp_refused", "tcp_timeout", "errors")


def scan_ip(ip, ports, timeout):
    row = dict.fromkeys(FIELDS, "")
    row["ip"] = str(ip)
    results = {"tcp_open": [], "tcp_refused": [], "tcp_timeout": [], "errors": []}
    for port in ports:
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                results["tcp_open"].append(str(port))
        except ConnectionRefusedError:
            results["tcp_refused"].append(str(port))
        except (TimeoutError, socket.timeout):
            results["tcp_timeout"].append(str(port))
        except OSError as exc:
            if exc.errno == errno.ETIMEDOUT:
                results["tcp_timeout"].append(str(port))
            else:
                results["errors"].append(f"TCP {port}: {exc}")

    try:
        row["reverse_dns"] = socket.gethostbyaddr(str(ip))[0]
    except socket.herror as exc:
        # HOST_NOT_FOUND and NO_DATA mean no PTR; other resolver failures are errors.
        if exc.errno not in (1, 4):
            results["errors"].append(f"DNS: {exc}")
    except OSError as exc:
        results["errors"].append(f"DNS: {exc}")

    if results["tcp_open"] or results["tcp_refused"]:
        row["status"] = "in_use"
    elif row["reverse_dns"]:
        row["status"] = "dns_only"
    elif results["errors"]:
        row["status"] = "unknown"
    else:
        row["status"] = "possibly_free"
    row.update({key: "; ".join(values) for key, values in results.items()})
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cidr", help="IPv4 CIDR, e.g. 10.41.92.0/24")
    parser.add_argument("-p", "--ports", default="22", help="comma-separated TCP ports (default: 22)")
    parser.add_argument("-o", "--output", default="ips.csv", help="new CSV file (default: ips.csv)")
    parser.add_argument("--timeout", type=float, default=1.0, help="seconds per TCP port (default: 1)")
    parser.add_argument("--workers", type=int, default=64, help="parallel hosts (default: 64)")
    args = parser.parse_args(argv)
    try:
        network = ipaddress.IPv4Network(args.cidr, strict=True)
        ports = list(dict.fromkeys(int(port) for port in args.ports.split(",")))
        if not ports or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("ports must be between 1 and 65535")
        if not 0 < args.timeout < float("inf") or args.workers < 1:
            raise ValueError("timeout must be finite and positive; workers must be positive")
        if network.num_addresses > 65536:
            raise ValueError("scan a /16 or smaller network at a time")
    except ValueError as exc:
        parser.error(str(exc))

    try:
        with open(args.output, "x", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=FIELDS)
            writer.writeheader()
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                for row in pool.map(lambda ip: scan_ip(ip, ports, args.timeout), network.hosts()):
                    writer.writerow(row)
    except (OSError, KeyboardInterrupt) as exc:
        print(f"Scan failed: {exc}. Any newly created CSV may be incomplete.", file=sys.stderr)
        return 1
    print(f"Saved {args.output}. 'possibly_free' is not proof an address is available.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
