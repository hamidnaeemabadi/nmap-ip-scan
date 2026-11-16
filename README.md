# TCP IP inventory

Python 3.9+ is required to start the script; no pip packages are needed.
Missing nmap is installed automatically using the OS package manager.
Default TCP connect scans run without root. The `fast` and `deep` tags require sudo
on macOS/Linux for raw-packet access.

```sh
python3 scan_ips.py 10.0.0.0/24
```

Defaults: SSH (TCP 22), a **2-second maximum probe timeout**, and **64 parallel
hosts**. Each host uses one nmap process. Default reports go into `./scan-reports/`,
created automatically relative to the current working directory. The CSV filename
includes the scanned CIDR followed by the local timestamp and microseconds,
e.g. `./scan-reports/ips_10.0.0.0_24_20261116_163045_123456.csv`.
Use `-o ips.csv` to choose an exact filename. Existing files are never overwritten.
The `/` in CIDR notation becomes `_`. No extra flag is needed. A custom
`-o report.csv` or `--output report.csv` is used exactly as supplied, without
adding a timestamp or CIDR.

Default scanning uses nmap `-sT -Pn -n --disable-arp-ping`: normal TCP connects,
no ICMP host discovery, and no separate nmap ARP discovery. The OS may still need
ARP to establish connections. Python performs reverse DNS using your system
resolver. Default scans send no application data. Deep scans actively probe
services and allow TCP/UDP/ICMP OS fingerprinting as described below.

## Automatic dependency setup

Before scanning, the script checks for nmap on PATH and in standard macOS/Windows
install folders. An existing installation is reused. Otherwise it runs:

- macOS: `brew install nmap`.
- Debian/Ubuntu: `apt-get update`, then `apt-get install -y nmap`.
- Fedora: `dnf install -y nmap`.
- Arch: `pacman -S --needed --noconfirm nmap`.
- Windows: `winget install --id Insecure.Nmap --exact --source winget --interactive`.

Linux installations use sudo when not already root. Password prompts can appear.
When the script runs through sudo on macOS, Homebrew runs as the original user
from `SUDO_USER`, since Homebrew cannot install packages as root.

Homebrew or WinGet must already be available; the script gives setup guidance if
they are missing. It does not bootstrap package managers or replace the Python
interpreter running it. Linux dependencies come from the configured repositories.
Package installations can need network access and privileges. Installer commands
and output are shown; failures stop before report creation or scanning.

After installing, the script finds nmap again, verifies `nmap --version`, and adds
its directory to this process's PATH, allowing scanning to continue without a new
terminal. It does not change your persistent shell/system PATH itself.

Windows may show installer, license, and UAC dialogs. Leave Npcap selected in the
Nmap installer: raw-packet scans need it. For `fast`/`deep`, a missing Npcap driver
triggers an interactive Nmap reinstall (`--force`), followed by another driver
check. Driver-file presence does not verify driver/service operation. Run raw scans
from an elevated terminal if your Npcap installation requires it. Ordinary TCP
connect scans with `-sT -Pn` can work without Npcap, except for Windows loopback
limitations. Dependencies such as the Visual C++ runtime are handled by the Nmap
installer. See [Nmap on Windows](https://nmap.org/book/inst-windows.html),
[WinGet install](https://learn.microsoft.com/en-us/windows/package-manager/winget/install),
and [Homebrew nmap](https://formulae.brew.sh/formula/nmap).

## Progress and verbosity

By default, the script prints a scan summary and a compact progress bar with
completed hosts, active nmap/DNS tasks, elapsed time, and estimated time remaining.
ETA starts as `estimating` until three hosts finish. It uses observed completion
throughput over the latest 64 host completions, at your actual worker count. This
reflects TCP/DNS latency, service/script waits, and local resource contention
without sending calibration probes or adding dependencies. It is not derived
from an assumed CPU speed or ping RTT. The estimate updates while waiting, so
stalls increase the displayed time remaining; it reaches `0s` only at completion.
Mixed fast/slow hosts, DNS stalls, and deep/vulnerability checks can make early
estimates optimistic or cause them to change substantially. Progress measures completed
hosts, not individual ports or scripts. While nmap is running, its port scanning,
version detection, OS detection, and NSE work are grouped under `nmap`.
Terminals refresh in place; redirected logs receive updates at most every five
seconds, plus the initial and final progress lines. Progress and diagnostics go
to stderr; the completion message goes to stdout.

```sh
python3 scan_ips.py 10.0.0.0/24 --tags devops
python3 scan_ips.py 10.0.0.0/24 --tags devops -v
python3 scan_ips.py 10.0.0.0/24 --tags devops -vv
python3 scan_ips.py 10.0.0.0/24 --tags devops -vvvv
```

- `-v`: each host's nmap/DNS stages and final occupancy/DNS result.
- `-vv`: additionally lists port results, errors, and detected service/OS/NSE details.
- `-vvv`: additionally prints exact nmap commands. `-vvvv` also uses this highest
  level; verbosity is capped at three levels. These flags control the Python
  script's output and do not change nmap's scanning behavior.

Hosts are counted as complete when scanning and reverse DNS finish. CSV rows remain
in IP order, so a slow earlier host can temporarily delay rows being written while
the progress count continues to advance. No additional Python packages are needed.

## Scan by tags

```sh
python3 scan_ips.py --list-tags
python3 scan_ips.py 10.0.0.0/24 --tags devops
python3 scan_ips.py 10.0.0.0/24 --tags linux windows
python3 scan_ips.py 10.0.0.0/24 --tags full
sudo python3 scan_ips.py 10.0.0.0/24 --tags devops fast
sudo python3 scan_ips.py 10.0.0.0/24 --tags linux deep
sudo python3 scan_ips.py 10.0.0.0/24 --tags full deep --workers 8
python3 scan_ips.py 10.0.0.0/24 --tags devops vuln --workers 8
sudo python3 scan_ips.py 10.0.0.0/24 --tags windows deep vuln --workers 8
```

- `devops`: the existing application, database, monitoring, Kubernetes control-plane,
  HashiCorp, Docker, DNS, and NFS service presets. Excludes Windows-specific
  management services and the large NodePort/dynamic RPC ranges.
- `linux`: SSH, HTTP/HTTPS, DNS, NFS, Docker API, and monitoring endpoints.
- `windows`: the `windows`, `active-directory`, and `mssql` presets.
- `full`: all TCP ports 1–65535. Overrides narrower port selections.
- `fast`: SYN scan (`-sS`), using the selected ports. An accepting port responds
  SYN/ACK, then the connection is reset without completing the handshake. This
  is not nmap's ACK scan (`-sA`). With no port/service tag, defaults to SSH/22.
- `deep`: TCP connect plus service/version detection (`-sV`), the `banner` script,
  and OS fingerprinting (`-O`). Defaults to the `devops` ports if no other port
  selections are given. Selected port tags, services, or `-p` replace that default.
- `vuln`: service/version detection (`-sV`) and nmap's NSE `vuln` category
  (`--script vuln`). Defaults to `devops` ports when no port selections are given.
  Combines with `deep` to run both banners and vulnerability scripts, or with
  `full` to check all TCP ports. Without `deep`, it does not enable OS fingerprinting.

Combine port tags with `fast` or `deep`; they are alternative scan modes and
cannot be combined with each other. With neither, TCP connect is used, including
for `full` and `vuln`. `fast` cannot combine with `vuln`, since vulnerability
checks make application connections beyond the SYN scan.
Tags accept spaces or commas and can be combined with `--services`
and `--ports`. `--list-tags` prints the exact service membership of each port tag.
Tags describe which ports to check; they do not filter hosts by operating system.
No tags or port options still means SSH/22/TCP, with 2s probe waits and 64 workers.

All modes skip ping discovery. **Deep OS detection additionally sends ICMP/UDP
fingerprinting probes**, even with `-Pn`; OS fingerprinting is enabled only for
the deep tag. NSE vulnerability scripts can generate their own additional traffic.
OS detection is limited to promising hosts with both an open and a closed TCP
port, and one fingerprinting attempt. Narrow selections such as only port 22
can therefore produce no OS fingerprint. Results are guesses with nmap's match
percentage, not verified inventory; service-derived OS hints are labeled separately.

Full scans check 65,535 ports per host. Deep scans send application probes and can
take substantially longer; reduce `--workers` for larger scans as needed. Nmap's
normal version-detection exclusions remain in place (including port 9100).
See [SYN scanning](https://nmap.org/book/synscan.html),
[banner grabbing](https://nmap.org/nsedoc/scripts/banner.html),
[OS detection limits](https://nmap.org/book/man-os-detection.html), and
[OS fingerprint probes](https://nmap.org/book/osdetect-methods.html).

## Vulnerability checks

The `vuln` tag runs the installed nmap `vuln` category against matching services;
it is not a complete vulnerability assessment or a guarantee of CVE coverage.
The category can include intrusive or disruptive checks and external lookups.
Run it only against authorized targets where those checks are appropriate, and
consider fewer workers than the default 64. These checks are never enabled by
default. No scripts are forced onto services whose script rules do not match.
See [NSE categories and selection](https://nmap.org/book/nse-usage.html).

Raw NSE results are saved in `script_results` with the script name and port or
host scope. Findings, negative results, errors, and structured-only results are
preserved without classifying the host as vulnerable based on text matching.
Scripts have a 60-second execution limit, and the scan gets the same additional
process time allowance as deep scans. No output can mean no matching script,
no finding, or a script that did not finish; a blank field does not mean secure.
Some individual scripts need elevated privileges even though the basic TCP
connect + `vuln` combination does not require root.

## Choose services or custom ports

```sh
python3 scan_ips.py --list-services
python3 scan_ips.py 10.0.0.0/24 --services ssh nginx redis mongodb
python3 scan_ips.py 10.0.0.0/24 --services elasticsearch kibana logstash tempo
python3 scan_ips.py 10.0.0.0/24 --services prometheus grafana
python3 scan_ips.py 10.0.0.0/24 --services ssh postgresql monitoring loki vault consul docker dns nfs smb
python3 scan_ips.py 10.0.0.0/24 --services ssh k8s -p 8443 --timeout 2 --workers 64
python3 scan_ips.py 10.0.0.0/24 --services k8s-nodeport
python3 scan_ips.py 10.0.0.0/24 --services windows active-directory
```

Preset names can also be comma-separated. Selected presets and `--ports` are
combined and deduplicated. With neither option, only SSH is selected; selecting
other services replaces that default, so include `ssh` if you want it too.
Custom ports accept inclusive ranges, e.g. `-p 22,80,30000-32767`.

Available TCP presets:

```text
ssh             22
nginx           80,443
elasticsearch   9200,9300
kibana          5601
logstash        5044,9600
tempo           3200,4317,4318
prometheus      9090
grafana         3000
redis           6379,16379,26379
rabbitmq        4369,5671,5672,15671,15672,25672
kafka           9092,9093
qdrant          6333,6334,6335
clickhouse      8123,8443,9000,9009,9440
hadoop          8020,8042,8088,9864,9866,9870,19888
haproxy         80,443,8404
k8s             2379,2380,6443,10250,10256,10257,10259
k8s-nodeport    30000-32767
mysql           3306,33060
mssql           1433
mongodb         27017,27018,27019
postgresql      5432
monitoring      9091,9093,9094,9100,9115
loki            3100,9095
vault           8200,8201
consul          8300,8301,8302,8500,8501,8600
docker          2375,2376
dns             53
nfs             2049
smb             445
rdp             3389
windows         135,139,445,3389,5985,5986
winrm           5985,5986
rpc             135
netbios         139
kerberos        88,464
ldap            389,636,3268,3269
active-directory 53,88,135,389,445,464,636,3268,3269,9389
rpc-dynamic     49152-65535
```

`monitoring` includes Pushgateway (9091), Alertmanager API/cluster (9093/9094),
Node Exporter (9100), and Blackbox Exporter (9115). Combine it with `prometheus`
and `grafana` to include their existing presets. `docker` probes remote daemon
ports, not container registries. `dns` probes TCP only; UDP is not tested.

`windows` combines RPC Endpoint Mapper, NetBIOS session service, SMB, RDP, and
WinRM HTTP/HTTPS. `active-directory` adds typical domain-controller endpoints:
DNS, Kerberos/password changes, RPC, LDAP/LDAPS, Global Catalog (3268/3269),
and AD Web Services (9389). These services must be installed/enabled and reachable;
they are not all enabled on every Windows host. NetBIOS is a legacy service.
`rpc-dynamic` is separate and opt-in: its 16,384 ports can make scans much slower.
These presets test only TCP, including the TCP side of services also using UDP.
See Microsoft's [Windows service port reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements)
and [WinRM defaults](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management).

These are common service, management, and cluster ports, not service identity
checks or an exhaustive inventory. HAProxy/NGINX listeners, Kafka listeners,
Logstash inputs, and other service ports are configurable. Port 5044 is a common
Logstash Beats input when configured. Hadoop covers common HDFS/YARN/JobHistory
ports; older Hadoop versions use different ports. The NodePort preset is opt-in:
it adds 2,768 ports per host and can make a subnet scan much slower.

Preset references: [Kubernetes](https://kubernetes.io/docs/reference/networking/ports-and-protocols/),
[Elastic](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/installing-elasticsearch),
[Tempo](https://github.com/grafana/tempo/blob/main/example/docker-compose/single-binary/docker-compose.yaml),
[Redis](https://redis.io/docs/latest/install/install-redis/),
[RabbitMQ](https://www.rabbitmq.com/docs/networking),
[Qdrant](https://qdrant.tech/documentation/installation/),
[MySQL](https://dev.mysql.com/doc/mysql-port-reference/en/mysql-port-reference-tables.html),
[MongoDB](https://www.mongodb.com/docs/manual/reference/default-mongodb-port/).

## CSV interpretation

One row per usable host, in address order: `ip`, `status`, `reverse_dns`,
`tcp_open`, `tcp_refused`, `tcp_timeout`, `errors`, `service_details`, and
`os_detection`, and `script_results`. The detection fields hold service/product/version,
banners, service OS hints, and OS fingerprint matches when available. Blank fields
mean no result was obtained. Values are separated by semicolons. Nmap may summarize
large port sets as ranges or counts. `tcp_refused` includes TCP reset responses
to SYN scans as well as refused connect attempts.

- `in_use`: at least one TCP connection opened or was explicitly refused.
- `dns_only`: a PTR name exists, but no tested port opened or refused. Treat as
  potentially reserved/in use; DNS records can be stale.
- `possibly_free`: all tested ports received no response and there is no PTR record.
- `unknown`: no TCP response or PTR name, and a scan/network/resolver error occurred.

`-Pn` tells nmap to assume hosts are up; that assumption is **not** used as evidence
of occupancy. Filtering reasons other than no response are recorded in `errors`.
TCP responses may come from a firewall or proxy. Silent hosts may be powered off
or filtered. **Check DHCP/IPAM before assigning an IP**: this scan cannot identify
actual reservations or prove an address is free. Reverse DNS does not verify that
the hostname resolves back to the address.

`--timeout` sets nmap's initial and maximum probe wait; adaptive waits can be
shorter. Retries are disabled, so packet loss can hide a host. This is not a
2-second deadline for the complete host or subnet scan. Deep/vulnerability version detection,
banner collection, and OS probing have their own waits and receive an additional
process time allowance. A process timeout is recorded as a scan error, not a free
IP. DNS uses the system resolver's timeout and can take longer.
See [nmap timing controls](https://nmap.org/book/man-performance.html).

The scanner accepts IPv4 networks from /16 through /32. Network and broadcast
addresses are omitted, except /31 and /32 follow Python's usable-host convention.
Interrupted/failed scans may leave a partial CSV. Per-host errors appear in the
CSV; inspect them even when the command completes. TCP connects can appear in logs.

## Tests

```sh
python3 -m unittest -v
```

Tests cover tags, scan-mode commands, privilege checks, presets, ranges, defaults,
timestamped output, CSV escaping, overwrite protection, XML summaries, banner/OS
fields, NSE result preservation, error classification, and a real localhost TCP
connect scan, plus progress rendering, heartbeat updates, verbosity levels, and
out-of-order host completion. SYN, OS fingerprint, and vulnerability commands are tested with
fixtures; no external network is scanned and no vulnerability scripts are executed.
OS installation paths, privilege handling, dependency failures, Windows Npcap
repair, and PATH refresh are tested with mocks; package installations are not run.
