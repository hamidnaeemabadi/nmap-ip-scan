#!/usr/bin/env python3
"""Inventory IPv4 hosts with tagged nmap scans and reverse DNS; skip ping discovery."""

import argparse
import csv
import ipaddress
import math
import os
import queue
import shlex
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from collections import Counter, deque
from datetime import datetime
from itertools import groupby, islice


FIELDS = ("ip", "status", "reverse_dns", "tcp_open", "tcp_refused", "tcp_timeout", "errors",
          "service_details", "os_detection", "script_results")

PRESETS = {
    "ssh": "22",
    "nginx": "80,443",
    "elasticsearch": "9200,9300",
    "kibana": "5601",
    "logstash": "5044,9600",
    "tempo": "3200,4317,4318",
    "prometheus": "9090",
    "grafana": "3000",
    "redis": "6379,16379,26379",
    "rabbitmq": "4369,5671,5672,15671,15672,25672",
    "kafka": "9092,9093",
    "qdrant": "6333,6334,6335",
    "clickhouse": "8123,8443,9000,9009,9440",
    "hadoop": "8020,8042,8088,9864,9866,9870,19888",
    "haproxy": "80,443,8404",
    "k8s": "2379,2380,6443,10250,10256,10257,10259",
    "k8s-nodeport": "30000-32767",
    "mysql": "3306,33060",
    "mssql": "1433",
    "mongodb": "27017,27018,27019",
    "postgresql": "5432",
    "monitoring": "9091,9093,9094,9100,9115",
    "loki": "3100,9095",
    "vault": "8200,8201",
    "consul": "8300,8301,8302,8500,8501,8600",
    "docker": "2375,2376",
    "dns": "53",
    "nfs": "2049",
    "smb": "445",
    "rdp": "3389",
    "windows": "135,139,445,3389,5985,5986",
    "winrm": "5985,5986",
    "rpc": "135",
    "netbios": "139",
    "kerberos": "88,464",
    "ldap": "389,636,3268,3269",
    "active-directory": "53,88,135,389,445,464,636,3268,3269,9389",
    "rpc-dynamic": "49152-65535",
}

PORT_TAGS = {
    "devops": (
        "ssh", "nginx", "elasticsearch", "kibana", "logstash", "tempo",
        "prometheus", "grafana", "redis", "rabbitmq", "kafka", "qdrant",
        "clickhouse", "hadoop", "haproxy", "k8s", "mysql", "mssql", "mongodb",
        "postgresql", "monitoring", "loki", "vault", "consul", "docker", "dns", "nfs",
    ),
    "linux": ("ssh", "nginx", "dns", "nfs", "docker", "monitoring"),
    "windows": ("windows", "active-directory", "mssql"),
}
MODE_TAGS = {
    "full": "all TCP ports 1-65535 (connect unless fast is also selected)",
    "fast": "SYN scan; selected ports, or SSH if none selected; requires root",
    "deep": "TCP connect + versions/banners + OS fingerprinting; requires root; allows ICMP/UDP OS probes",
    "vuln": "service/version detection + NSE vuln scripts; active checks may be intrusive",
}


def scan_selection(tags, services, custom):
    names = [tag for group in tags for tag in group.split(",")]
    unknown = set(names) - PORT_TAGS.keys() - MODE_TAGS.keys()
    if unknown:
        raise ValueError(f"unknown tags: {', '.join(sorted(unknown))}; use --list-tags")
    if "fast" in names and "deep" in names:
        raise ValueError("fast and deep are alternative scan modes; select only one")
    if "fast" in names and "vuln" in names:
        raise ValueError("fast is SYN-only; use vuln without fast for active service checks")
    selected = list(services)
    for name in names:
        selected.extend(PORT_TAGS.get(name, ()))
    if {"deep", "vuln"}.intersection(names) and not selected and custom is None:
        selected.extend(PORT_TAGS["devops"])
    ports = select_ports(selected, custom)
    if "full" in names:
        ports = list(range(1, 65536))
    mode = "deep" if "deep" in names else "fast" if "fast" in names else "connect"
    return ports, mode


def select_ports(services, custom):
    specs = [custom] if custom is not None else []
    for name in services:
        for service in name.split(","):
            if service not in PRESETS:
                raise ValueError(f"unknown service: {service}; use --list-services")
            specs.append(PRESETS[service])
    ports = set()
    for spec in specs or [PRESETS["ssh"]]:
        for part in spec.split(","):
            bounds = part.split("-")
            if len(bounds) > 2:
                raise ValueError(f"invalid port range: {part}")
            start, end = int(bounds[0]), int(bounds[-1])
            if not 1 <= start <= end <= 65535:
                raise ValueError("ports must be between 1 and 65535, with ascending ranges")
            ports.update(range(start, end + 1))
    return sorted(ports)


def tcp_results(xml, expected_count):
    root = ET.fromstring(xml)
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("nmap did not finish successfully")
    results = {key: [] for key in FIELDS[3:]}
    count = 0

    def record(state, reason, label):
        if state == "open":
            results["tcp_open"].append(label)
        elif state == "closed" and reason in ("conn-refused", "reset"):
            results["tcp_refused"].append(label)
        elif state == "filtered" and reason == "no-response":
            results["tcp_timeout"].append(label)
        else:
            results["errors"].append(f"TCP {label}: {state} ({reason})")

    for port in root.findall("host/ports/port"):
        state = port.find("state")
        record(state.get("state"), state.get("reason"), port.get("portid"))
        count += 1
        service = port.find("service")
        if service is not None and service.get("method") == "probed":
            details = " ".join(filter(None, (service.get(key) for key in
                                             ("name", "product", "version", "extrainfo", "tunnel"))))
            results["service_details"].append(f"{port.get('portid')}/tcp: {details}")
            if service.get("ostype"):
                results["os_detection"].append(f"{service.get('ostype')} (service hint via {port.get('portid')}/tcp)")
        for banner in port.findall("script[@id='banner']"):
            results["service_details"].append(f"{port.get('portid')}/tcp banner: {banner.get('output', '')}")
        for script in port.findall("script"):
            if script.get("id") != "banner":
                output = script.get("output") or ET.tostring(script, encoding="unicode")
                results["script_results"].append(f"{port.get('portid')}/tcp {script.get('id')}: {output}")
    for group in root.findall("host/ports/extraports"):
        group_count = int(group.get("count"))
        reasons = group.findall("extrareasons")
        if sum(int(reason.get("count")) for reason in reasons) != group_count:
            raise ValueError("incomplete nmap port summary")
        for reason in reasons:
            label = reason.get("ports") or f"{reason.get('count')} ports"
            record(group.get("state"), reason.get("reason"), label)
        count += group_count
    if count != expected_count:
        raise ValueError(f"nmap reported {count} of {expected_count} ports")
    for match in root.findall("host/os/osmatch"):
        results["os_detection"].append(f"{match.get('name')} (fingerprint match {match.get('accuracy')}%)")
    for scope, path in (("host", "host/hostscript/script"),
                        ("pre-scan", "prescript/script"), ("post-scan", "postscript/script")):
        for script in root.findall(path):
            output = script.get("output") or ET.tostring(script, encoding="unicode")
            results["script_results"].append(f"{scope} {script.get('id')}: {output}")
    return results


def scan_ip(ip, ports, timeout, mode="connect", vuln=False, events=None):
    row = dict.fromkeys(FIELDS, "")
    row["ip"] = str(ip)
    results = {"tcp_open": [], "tcp_refused": [], "tcp_timeout": [], "errors": []}
    port_ranges = []
    for _, group in groupby(enumerate(ports), lambda item: item[1] - item[0]):
        run = [port for _, port in group]
        port_ranges.append(str(run[0]) if len(run) == 1 else f"{run[0]}-{run[-1]}")
    scan_flags = ["-sS"] if mode == "fast" else ["-sT"]
    if mode == "deep" or vuln:
        scan_flags.append("-sV")
        scripts = (["banner"] if mode == "deep" else []) + (["vuln"] if vuln else [])
        scan_flags += ["--script", ",".join(scripts), "--script-timeout", "60s" if vuln else "10s"]
    if mode == "deep":
        scan_flags += ["-O", "--osscan-limit", "--max-os-tries", "1"]
    command = [
        "nmap", *scan_flags, "-Pn", "-n", "--disable-arp-ping", "--reason",
        "--initial-rtt-timeout", f"{timeout:g}s", "--max-rtt-timeout", f"{timeout:g}s",
        "--max-retries", "0", "-p", ",".join(port_ranges), "-oX", "-", str(ip),
    ]
    if events is not None:
        events.put((str(ip), "nmap", shlex.join(command)))
    try:
        extra_time = 300 if mode == "deep" or vuln else 10
        completed = subprocess.run(command, capture_output=True, text=True, check=True,
                                   timeout=max(extra_time, timeout * len(ports) + extra_time))
        results = tcp_results(completed.stdout, len(ports))
        if completed.stderr.strip():
            results["errors"].append(f"nmap: {completed.stderr.strip()}")
    except (OSError, subprocess.SubprocessError, ET.ParseError, ValueError, AttributeError) as exc:
        results["errors"].append(f"nmap: {exc}")

    if events is not None:
        events.put((str(ip), "DNS", ""))
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


class Progress:
    def __init__(self, total):
        self.total = total
        self.started = time.monotonic()
        self.last_draw = self.started
        self.tty = sys.stderr.isatty()
        self.width = 0
        self.samples = deque([(self.started, 0)], maxlen=65)

    def record(self, done):
        self.samples.append((time.monotonic(), done))

    def estimate(self, done, now):
        if done == self.total:
            return "0s"
        since, previous_done = self.samples[0]
        elapsed = now - since
        count = done - previous_done
        if done < 3 or count <= 0 or elapsed <= 0:
            return "estimating"
        # Wall time includes scan/DNS latency and contention at the actual worker count.
        seconds = math.ceil((self.total - done) * elapsed / count)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        if hours:
            return f"~{hours}h{minutes:02d}m"
        if minutes:
            return f"~{minutes}m{seconds:02d}s"
        return f"~{seconds}s"

    def log(self, message):
        if self.tty:
            print("\r" + " " * self.width + "\r", end="", file=sys.stderr)
        print(" ".join(str(message).splitlines()), file=sys.stderr, flush=True)
        self.width = 0

    def draw(self, done, phases, force=False):
        now = time.monotonic()
        if not force and now - self.last_draw < (0.2 if self.tty else 5):
            return
        counts = Counter(phases.values())
        filled = 20 * done // self.total
        line = (f"[{'#' * filled}{'-' * (20 - filled)}] {done}/{self.total} "
                f"({100 * done // self.total}%) | nmap {counts['nmap']} DNS {counts['DNS']} "
                f"| elapsed {now - self.started:.0f}s | ETA {self.estimate(done, now)}")
        print("\r" + line.ljust(self.width) if self.tty else line,
              end="" if self.tty else "\n", file=sys.stderr, flush=True)
        self.width = len(line)
        self.last_draw = now

    def close(self):
        if self.tty:
            print(file=sys.stderr, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cidr", nargs="?", help="IPv4 CIDR, e.g. 10.0.0.0/24")
    parser.add_argument("-p", "--ports", help="TCP ports/ranges, e.g. 22,80,30000-32767")
    parser.add_argument("--services", nargs="+", default=[], help="service presets; combines with --ports (default: ssh)")
    parser.add_argument("--tags", nargs="+", default=[], help="combine port tags devops/linux/windows with full/fast/deep/vuln")
    parser.add_argument("--list-tags", action="store_true", help="list port groups and scan modes and exit")
    parser.add_argument("--list-services", action="store_true", help="list service presets and exit")
    parser.add_argument("-o", "--output", help="exact CSV path (default: ./scan-reports/ips_NETWORK_PREFIX_TIMESTAMP.csv)")
    parser.add_argument("--timeout", type=float, default=2.0, help="maximum nmap probe timeout in seconds (default: 2)")
    parser.add_argument("--workers", type=int, default=64, help="parallel hosts (default: 64)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="verbosity: -v host stages, -vv results, -vvv commands (-vvvv also level 3)")
    args = parser.parse_args(argv)
    args.verbose = min(args.verbose, 3)
    if args.list_tags:
        for name, services in PORT_TAGS.items():
            print(f"{name}: {', '.join(services)}")
        for name, description in MODE_TAGS.items():
            print(f"{name}: {description}")
        return 0
    if args.list_services:
        for name, spec in PRESETS.items():
            print(f"{name}: {spec}")
        return 0
    if args.cidr is None:
        parser.error("cidr is required")
    try:
        network = ipaddress.IPv4Network(args.cidr, strict=True)
        ports, mode = scan_selection(args.tags, args.services, args.ports)
        vuln = any("vuln" in group.split(",") for group in args.tags)
        if not 0.1 <= args.timeout < float("inf") or args.workers < 1:
            raise ValueError("timeout must be finite and at least 0.1s; workers must be positive")
        if network.num_addresses > 65536:
            raise ValueError("scan a /16 or smaller network at a time")
    except ValueError as exc:
        parser.error(str(exc))
    if shutil.which("nmap") is None:
        parser.error("nmap is required; install it and ensure it is on PATH")
    if mode in ("fast", "deep") and hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error(f"the {mode} tag requires raw-packet privileges; run this command with sudo")
    try:
        if args.output is None:
            os.makedirs("scan-reports", exist_ok=True)
            timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
            args.output = f"scan-reports/ips_{network.network_address}_{network.prefixlen}_{timestamp}.csv"
        with open(args.output, "x", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=FIELDS)
            writer.writeheader()
            total = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
            progress = Progress(total)
            events = queue.Queue()
            phases = {}
            hosts = enumerate(network.hosts())
            rows = {}
            completed = next_row = 0
            print(f"Scanning {args.cidr}: {total} hosts, {len(ports)} TCP ports/host, "
                  f"{mode}{' + vuln' if vuln else ''}, {args.workers} workers. "
                  f"Reverse DNS enabled. Report: {args.output}", file=sys.stderr)
            progress.draw(0, phases, force=True)
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                pending = {pool.submit(scan_ip, ip, ports, args.timeout, mode, vuln, events): index
                           for index, ip in islice(hosts, args.workers)}
                try:
                    while pending:
                        finished, _ = wait(pending, timeout=0.2, return_when=FIRST_COMPLETED)
                        while True:
                            try:
                                ip, phase, detail = events.get_nowait()
                            except queue.Empty:
                                break
                            phases[ip] = phase
                            if args.verbose:
                                progress.log(f"{ip}: {phase}")
                            if args.verbose >= 3 and detail:
                                progress.log(f"{ip}: {detail}")
                        for future in finished:
                            index = pending.pop(future)
                            row = future.result()
                            phases.pop(row['ip'], None)
                            rows[index] = row
                            completed += 1
                            progress.record(completed)
                            if args.verbose:
                                progress.log(f"{row['ip']}: {row.get('status', 'done')} "
                                             f"DNS={row.get('reverse_dns') or '-'}")
                            if args.verbose >= 2:
                                for field in FIELDS[3:]:
                                    if row.get(field):
                                        progress.log(f"{row['ip']} {field}: {row[field]}")
                            while next_row in rows:
                                writer.writerow(rows.pop(next_row))
                                next_row += 1
                            next_host = next(hosts, None)
                            if next_host is not None:
                                index, ip = next_host
                                pending[pool.submit(scan_ip, ip, ports, args.timeout, mode, vuln, events)] = index
                        progress.draw(completed, phases, force=not pending)
                finally:
                    progress.close()
    except (OSError, KeyboardInterrupt) as exc:
        print(f"Scan failed: {exc}. Any newly created CSV may be incomplete.", file=sys.stderr)
        return 1
    print(f"Saved {args.output}. 'possibly_free' is not proof an address is available.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
