# TCP IP inventory

Python 3.9+; standard library only. No nmap, root privileges, or ICMP probes required.

```sh
python3 scan_ips.py 10.41.92.0/24 -o ips.csv
```

This attempts a normal TCP connection to port 22 on every usable host address,
then performs reverse DNS using your system resolver. Unlike nmap's default
host discovery, every host is probed directly. No application data is sent.

To probe more services:

```sh
python3 scan_ips.py 10.41.92.0/24 -p 22,80,443 --timeout 1 --workers 64 -o ips-services.csv
```

The CSV contains one row per host, in address order, with `ip`, `status`,
`reverse_dns`, `tcp_open`, `tcp_refused`, `tcp_timeout`, and `errors` columns.
Port lists are separated by semicolons.

- `in_use`: at least one TCP connection opened or was explicitly refused.
- `dns_only`: a PTR name exists, but no tested port opened or refused. Treat as
  potentially reserved/in use; DNS records can be stale.
- `possibly_free`: all tested ports timed out and there is no PTR record.
- `unknown`: no TCP response or PTR name, and a network/resolver error occurred.

TCP responses may come from a firewall or proxy. Silent hosts may be powered off
or filtered. **Check DHCP/IPAM before assigning an IP**: this scan cannot identify
actual reservations or prove an address is free. Reverse DNS does not verify that
the hostname resolves back to the address.

`--timeout` applies to each TCP attempt; DNS uses the system resolver's timeout
and can take longer. Ports are tried sequentially per host; hosts run in parallel.
The scanner accepts IPv4 networks from /16 through /32. Network and broadcast
addresses are omitted, except /31 and /32 follow Python's usable-host convention.
Existing output files are never overwritten. Interrupted/failed scans may leave
a partial CSV. TCP connects can appear in service logs.

Run the local checks (no external network needed):

```sh
python3 -m unittest -v
```
