import csv
import io
import os
import socket
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import mock_open, patch

from scan_ips import (PRESETS, PORT_TAGS, Progress, ensure_requirements, find_nmap,
                      installation_commands, main, scan_ip, scan_selection, select_ports, tcp_results)


def scan_xml(state="closed", reason="conn-refused"):
    return (f'<nmaprun><host><ports><port portid="22"><state state="{state}" '
            f'reason="{reason}"/></port></ports></host>'
            '<runstats><finished exit="success"/></runstats></nmaprun>')


class ScanTests(unittest.TestCase):
    def test_linux_install_commands_and_privilege_handling(self):
        for distro, manager in (("debian", "apt-get"), ("ubuntu", "apt-get"),
                                ("fedora", "dnf"), ("arch", "pacman")):
            for uid in (0, 1000):
                with self.subTest(distro=distro, uid=uid):
                    with patch("scan_ips.sys.platform", "linux"), patch("scan_ips.os.geteuid", return_value=uid):
                        with patch("scan_ips.open", mock_open(read_data=f'ID="{distro}"\n')):
                            with patch("scan_ips.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
                                commands = installation_commands()
                    self.assertEqual(commands[-1][-1], "nmap")
                    self.assertEqual(commands[-1][0], "sudo" if uid else manager)
                    self.assertEqual(len(commands), 2 if manager == "apt-get" else 1)

    def test_macos_and_windows_install_commands(self):
        with patch("scan_ips.sys.platform", "darwin"), patch("scan_ips.os.geteuid", return_value=1000):
            with patch("scan_ips.shutil.which", return_value="/opt/homebrew/bin/brew"):
                self.assertEqual(installation_commands(), [["/opt/homebrew/bin/brew", "install", "nmap"]])
                with patch("scan_ips.os.geteuid", return_value=0), patch.dict(os.environ, {"SUDO_USER": "tester"}):
                    self.assertEqual(installation_commands()[0][:3], ["sudo", "-u", "tester"])
        with patch("scan_ips.sys.platform", "win32"), patch("scan_ips.shutil.which", return_value="winget.exe"):
            command = installation_commands(repair=True)[0]
            self.assertIn("Insecure.Nmap", command)
            self.assertIn("--interactive", command)
            self.assertIn("--force", command)

    def test_dependency_installation_verification_and_path_refresh(self):
        with patch("scan_ips.find_nmap", side_effect=[None, "/installed/bin/nmap"]):
            with patch("scan_ips.sys.platform", "linux"), patch("scan_ips.installation_commands", return_value=[["installer", "nmap"]]):
                with patch("scan_ips.subprocess.run") as run, patch.dict(os.environ, {"PATH": "/usr/bin"}):
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(ensure_requirements(), "/installed/bin/nmap")
                    self.assertEqual(run.call_count, 2)
                    self.assertEqual(run.call_args_list[0].args[0], ["installer", "nmap"])
                    self.assertEqual(run.call_args_list[1].args[0], ["/installed/bin/nmap", "--version"])
                    self.assertEqual(os.environ["PATH"].split(os.pathsep)[0], "/installed/bin")

    def test_installed_nmap_is_not_reinstalled(self):
        with patch("scan_ips.find_nmap", return_value="nmap"), patch("scan_ips.sys.platform", "linux"):
            with patch("scan_ips.subprocess.run") as run:
                self.assertEqual(ensure_requirements(), "nmap")
                run.assert_not_called()

    def test_windows_npcap_repair_for_raw_scans(self):
        with patch("scan_ips.sys.platform", "win32"), patch("scan_ips.find_nmap", return_value="nmap.exe"):
            with patch("scan_ips.npcap_installed", side_effect=[False, True]):
                with patch("scan_ips.installation_commands", return_value=[["winget", "install"]]) as install:
                    with patch("scan_ips.subprocess.run"), redirect_stderr(io.StringIO()):
                        ensure_requirements(raw_packets=True)
                    install.assert_called_once_with(repair=True)

    def test_dependency_failures_stop_before_scan(self):
        for problem in (RuntimeError("no package manager"), OSError("installation failed"),
                        subprocess.CalledProcessError(1, ["installer"])):
            with patch("scan_ips.ensure_requirements", side_effect=problem):
                with patch("scan_ips.open") as output, redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        main(["192.0.2.1/32"])
                    self.assertEqual(error.exception.code, 2)
                    output.assert_not_called()
        with patch("scan_ips.find_nmap", return_value=None), patch("scan_ips.sys.platform", "linux"):
            with patch("scan_ips.installation_commands", return_value=[["installer"]]), patch("scan_ips.subprocess.run"):
                with redirect_stderr(io.StringIO()), self.assertRaisesRegex(RuntimeError, "not found"):
                    ensure_requirements()

    def test_missing_package_manager_and_unsupported_os(self):
        for platform in ("darwin", "win32", "freebsd"):
            with patch("scan_ips.sys.platform", platform), patch("scan_ips.shutil.which", return_value=None):
                with patch("scan_ips.os.path.isfile", return_value=False), self.assertRaises(RuntimeError):
                    installation_commands()
        with patch("scan_ips.sys.platform", "linux"), patch("scan_ips.open", mock_open(read_data="ID=unsupported\n")):
            with self.assertRaisesRegex(RuntimeError, "unsupported Linux"):
                installation_commands()

    def test_nmap_discovered_outside_windows_path(self):
        with patch("scan_ips.sys.platform", "win32"), patch("scan_ips.shutil.which", return_value=None):
            with patch("scan_ips.os.path.isfile", return_value=True), patch("scan_ips.os.access", return_value=True):
                self.assertTrue(find_nmap().endswith("nmap.exe"))

    def test_presets_and_ranges(self):
        self.assertEqual(select_ports([], None), [22])
        self.assertEqual(select_ports(["ssh,nginx", "grafana"], "22,3000-3001"),
                         [22, 80, 443, 3000, 3001])
        nodeports = select_ports(["k8s-nodeport"], None)
        self.assertEqual((nodeports[0], nodeports[-1], len(nodeports)), (30000, 32767, 2768))
        for name in PRESETS:
            self.assertTrue(select_ports([name], None))
        for spec in ("0", "65536", "30-20", "22,,80", "1-2-3"):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                select_ports([], spec)
        with self.assertRaises(ValueError):
            select_ports(["unknown"], None)

    def test_infrastructure_presets_combine_with_ssh(self):
        services = ["ssh", "postgresql", "monitoring", "loki", "vault",
                    "consul", "docker", "dns", "nfs", "smb"]
        self.assertEqual(select_ports(services, "22,5432"), [
            22, 53, 445, 2049, 2375, 2376, 3100, 5432, 8200, 8201,
            8300, 8301, 8302, 8500, 8501, 8600, 9091, 9093, 9094,
            9095, 9100, 9115,
        ])

    def test_windows_presets_and_opt_in_rpc_range(self):
        ports = select_ports(["windows", "active-directory", "winrm", "rpc",
                              "netbios", "kerberos", "ldap", "rdp", "smb"], None)
        self.assertEqual(ports, [53, 88, 135, 139, 389, 445, 464, 636,
                                 3268, 3269, 3389, 5985, 5986, 9389])
        self.assertFalse(any(port >= 49152 for port in ports))
        dynamic = select_ports(["rpc-dynamic"], None)
        self.assertEqual((dynamic[0], dynamic[-1], len(dynamic)), (49152, 65535, 16384))

    def test_classification_and_command(self):
        for state, reason, name, expected in [
            ("open", "syn-ack", None, "in_use"),
            ("closed", "conn-refused", None, "in_use"),
            ("filtered", "no-response", None, "possibly_free"),
            ("filtered", "no-response", "host.example", "dns_only"),
            ("filtered", "admin-prohibited", None, "unknown"),
        ]:
            with self.subTest(state=state, expected=expected):
                completed = subprocess.CompletedProcess([], 0, scan_xml(state, reason), "")
                with patch("scan_ips.subprocess.run", return_value=completed) as run:
                    with patch("scan_ips.socket.gethostbyaddr") as dns:
                        if name:
                            dns.return_value = (name, [], [])
                        else:
                            dns.side_effect = socket.herror(1, "no PTR")
                        row = scan_ip("192.0.2.1", [22], 2)
                self.assertEqual(row["status"], expected)
                command = run.call_args.args[0]
                for flag in ("-sT", "-Pn", "-n", "--disable-arp-ping"):
                    self.assertIn(flag, command)
                self.assertEqual(command[command.index("--max-rtt-timeout") + 1], "2s")

    def test_tag_selection(self):
        self.assertEqual(scan_selection([], [], None), ([22], "connect"))
        self.assertEqual(scan_selection(["fast"], [], None), ([22], "fast"))
        ports, mode = scan_selection(["linux,windows", "fast"], ["redis"], "8443")
        self.assertEqual(mode, "fast")
        self.assertEqual(ports, select_ports([*PORT_TAGS["linux"], *PORT_TAGS["windows"], "redis"], "8443"))
        ports, mode = scan_selection(["full", "fast"], [], None)
        self.assertEqual((ports[0], ports[-1], len(ports), mode), (1, 65535, 65535, "fast"))
        self.assertEqual(scan_selection(["deep"], [], None),
                         (select_ports(list(PORT_TAGS["devops"]), None), "deep"))
        self.assertEqual(scan_selection(["vuln"], [], None),
                         (select_ports(list(PORT_TAGS["devops"]), None), "connect"))
        for tags in (["unknown"], ["fast", "deep"], ["fast", "vuln"]):
            with self.assertRaises(ValueError):
                scan_selection(tags, [], None)

    def test_scan_mode_flags_and_full_range_compression(self):
        for mode, flag in [("connect", "-sT"), ("fast", "-sS"), ("deep", "-sT")]:
            with self.subTest(mode=mode):
                completed = subprocess.CompletedProcess([], 0, scan_xml(), "")
                with patch("scan_ips.subprocess.run", return_value=completed) as run:
                    with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(1, "no PTR")):
                        scan_ip("192.0.2.1", list(range(1, 65536)), 2, mode)
                command = run.call_args.args[0]
                self.assertIn(flag, command)
                self.assertIn("-Pn", command)
                self.assertEqual(command[command.index("-p") + 1], "1-65535")
                self.assertEqual("-O" in command, mode == "deep")
                self.assertEqual("-sV" in command, mode == "deep")
                self.assertEqual("banner" in command, mode == "deep")
                self.assertNotIn("-sA", command)

    def test_banner_and_os_csv_fields(self):
        xml = scan_xml("open", "syn-ack").replace(
            '</port>', '<service name="ssh" product="OpenSSH" version="9.9" ostype="Linux" method="probed"/>'
            '<script id="banner" output="SSH-2.0-OpenSSH_9.9"/></port>').replace(
            '</host>', '<os><osmatch name="Linux 6.x" accuracy="95"/></os></host>')
        parsed = tcp_results(xml, 1)
        self.assertIn("22/tcp: ssh OpenSSH 9.9", parsed["service_details"])
        self.assertIn("22/tcp banner: SSH-2.0-OpenSSH_9.9", parsed["service_details"])
        self.assertIn("Linux 6.x (fingerprint match 95%)", parsed["os_detection"])
        self.assertIn("Linux (service hint via 22/tcp)", parsed["os_detection"])
        with patch("scan_ips.subprocess.run", return_value=subprocess.CompletedProcess([], 0, xml, "")):
            with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(1, "no PTR")):
                row = scan_ip("192.0.2.1", [22], 2, "deep")
        self.assertIn("OpenSSH 9.9", row["service_details"])
        self.assertIn("fingerprint match 95%", row["os_detection"])

    def test_vulnerability_scripts_and_csv_results(self):
        xml = scan_xml("open", "syn-ack").replace(
            '</port>', '<script id="http-vuln-example" output="VULNERABLE: example&#10;details, quoted"/></port>'
        ).replace('</host>', '<hostscript><script id="smb-vuln-example" output="NOT VULNERABLE"/>'
                  '<script id="structured-example"><table><elem key="state">UNKNOWN</elem></table></script>'
                  '</hostscript></host>')
        for mode, expression in (("connect", "vuln"), ("deep", "banner,vuln")):
            with self.subTest(mode=mode):
                with patch("scan_ips.subprocess.run", return_value=subprocess.CompletedProcess([], 0, xml, "")) as run:
                    with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(1, "no PTR")):
                        row = scan_ip("192.0.2.1", [22], 2, mode, True)
                command = run.call_args.args[0]
                self.assertIn("-sV", command)
                self.assertIn("-Pn", command)
                self.assertEqual(command[command.index("--script") + 1], expression)
                self.assertEqual(command[command.index("--script-timeout") + 1], "60s")
                self.assertEqual(command.count("--script"), 1)
                self.assertIn("VULNERABLE: example\ndetails, quoted", row["script_results"])
                self.assertIn("host smb-vuln-example: NOT VULNERABLE", row["script_results"])
                self.assertIn('key="state">UNKNOWN', row["script_results"])
                stream = io.StringIO(newline="")
                writer = csv.DictWriter(stream, fieldnames=row.keys())
                writer.writeheader()
                writer.writerow(row)
                stream.seek(0)
                self.assertEqual(next(csv.DictReader(stream))["script_results"], row["script_results"])

    def test_vuln_tag_reaches_worker_without_enabling_os_detection(self):
        with patch("scan_ips.shutil.which", return_value="nmap"), patch("scan_ips.os.geteuid", return_value=501):
            with patch("scan_ips.open"), patch("scan_ips.os.makedirs"), patch("scan_ips.scan_ip", return_value={"ip": "192.0.2.1"}) as scan:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["192.0.2.1/32", "--tags", "linux,vuln"]), 0)
                self.assertEqual(scan.call_args.args[1:-1],
                                 (select_ports(list(PORT_TAGS["linux"]), None), 2.0, "connect", True))

    def test_privileged_tags_fail_before_creating_csv(self):
        for mode in ("fast", "deep"):
            with patch("scan_ips.os.geteuid", return_value=501), patch("scan_ips.shutil.which", return_value="nmap"):
                with patch("scan_ips.open") as output, redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        main(["192.0.2.1/32", "--tags", mode])
                    self.assertEqual(error.exception.code, 2)
                    output.assert_not_called()

    def test_aggregate_xml_and_incomplete_results(self):
        xml = ('<nmaprun><host><ports><extraports state="closed" count="2768">'
               '<extrareasons reason="conn-refused" count="2768" ports="30000-32767"/>'
               '</extraports></ports></host><runstats><finished exit="success"/></runstats></nmaprun>')
        self.assertEqual(tcp_results(xml, 2768)["tcp_refused"], ["30000-32767"])
        with self.assertRaises(ValueError):
            tcp_results(scan_xml(), 2)
        with self.assertRaises(ValueError):
            tcp_results(xml.replace('count="2768" ports=', 'count="1" ports='), 2768)

    def test_failures_are_unknown(self):
        for output, error in [("broken XML", None), ("", OSError("nmap failed"))]:
            completed = subprocess.CompletedProcess([], 0, output, "")
            with patch("scan_ips.subprocess.run", return_value=completed, side_effect=error):
                with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(1, "no PTR")):
                    self.assertEqual(scan_ip("192.0.2.1", [22], 2)["status"], "unknown")

    def test_csv_defaults_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ips.csv"
            with patch("scan_ips.shutil.which", return_value="nmap"):
                with patch("scan_ips.scan_ip", return_value={"ip": "192.0.2.1", "reverse_dns": "host,example"}) as scan:
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(main(["192.0.2.1/32", "-o", str(output)]), 0)
                    self.assertEqual(scan.call_args.args[1:-1], ([22], 2.0, "connect", False))
                before = output.read_bytes()
                with output.open(newline="") as stream:
                    self.assertEqual(list(csv.DictReader(stream))[0]["reverse_dns"], "host,example")
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["192.0.2.1/32", "-o", str(output)]), 1)
                self.assertEqual(output.read_bytes(), before)

    def test_timestamp_and_workers(self):
        with patch("scan_ips.shutil.which", return_value="nmap"), patch("scan_ips.open") as output:
            with patch("scan_ips.os.makedirs") as mkdir, patch("scan_ips.ThreadPoolExecutor", wraps=ThreadPoolExecutor) as pool:
                with patch("scan_ips.scan_ip", return_value={"ip": "192.0.2.1"}), redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["192.0.2.1/32"]), 0)
            pool.assert_called_once_with(max_workers=64)
            mkdir.assert_called_once_with("scan-reports", exist_ok=True)
            self.assertRegex(output.call_args.args[0], r"^scan-reports/ips_192\.0\.2\.1_32_\d{8}_\d{6}_\d{6}\.csv$")

    def test_cidr_in_default_name_and_exact_custom_report_names(self):
        cases = [
            ([], r"^scan-reports/ips_192\.0\.2\.0_30_\d{8}_\d{6}_\d{6}\.csv$"),
            (["-o", "folder.with.dots/report.csv"], r"^folder\.with\.dots/report\.csv$"),
            (["--output", "report"], r"^report$"),
        ]
        for extra, expected in cases:
            with self.subTest(extra=extra):
                with patch("scan_ips.shutil.which", return_value="nmap"), patch("scan_ips.os.makedirs"):
                    with patch("scan_ips.open") as output, patch("scan_ips.scan_ip", side_effect=lambda ip, *args: {"ip": str(ip)}):
                        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                            self.assertEqual(main(["192.0.2.0/30", *extra]), 0)
                        self.assertRegex(output.call_args.args[0], expected)

    def test_default_report_folder_created_and_reused(self):
        previous_directory = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                with patch("scan_ips.shutil.which", return_value="nmap"):
                    with patch("scan_ips.scan_ip", return_value={"ip": "192.0.2.1"}), redirect_stdout(io.StringIO()):
                        self.assertEqual(main(["192.0.2.1/32"]), 0)
                        self.assertEqual(main(["192.0.2.1/32"]), 0)
                reports = list(Path("scan-reports").glob("ips_*.csv"))
                self.assertEqual(len(reports), 2)
                for report in reports:
                    with report.open(newline="") as stream:
                        self.assertEqual(next(csv.DictReader(stream))["ip"], "192.0.2.1")
            finally:
                os.chdir(previous_directory)

    def test_report_directory_error_is_reported(self):
        with patch("scan_ips.shutil.which", return_value="nmap"):
            with patch("scan_ips.os.makedirs", side_effect=PermissionError("no access")):
                with patch("scan_ips.open") as output, redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["192.0.2.1/32"]), 1)
                    output.assert_not_called()

    def test_progress_and_three_verbosity_levels(self):
        with tempfile.TemporaryDirectory() as directory:
            for level in range(5):
                with self.subTest(level=level):
                    messages = io.StringIO()
                    args = ["192.0.2.1/32", "-o", str(Path(directory) / f"level-{level}.csv")]
                    if level:
                        args.append("-" + "v" * level)
                    with patch("scan_ips.shutil.which", return_value="nmap"):
                        with patch("scan_ips.subprocess.run", return_value=subprocess.CompletedProcess([], 0, scan_xml(), "")):
                            with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(1, "no PTR")):
                                with redirect_stderr(messages), redirect_stdout(io.StringIO()):
                                    self.assertEqual(main(args), 0)
                    output = messages.getvalue()
                    self.assertIn("1/1 (100%)", output)
                    self.assertIn("ETA estimating", output)
                    self.assertIn("ETA 0s", output)
                    self.assertIn("Reverse DNS enabled", output)
                    self.assertEqual("192.0.2.1: nmap" in output, level >= 1)
                    self.assertEqual("192.0.2.1 tcp_refused: 22" in output, level >= 2)
                    self.assertEqual("nmap -sT -Pn" in output, level >= 3)
                    self.assertNotIn("\r", output)

    def test_progress_heartbeat_and_terminal_rendering(self):
        messages = io.StringIO()
        with redirect_stderr(messages), patch("scan_ips.time.monotonic", side_effect=[0, 0, 0.1, 6]):
            progress = Progress(2)
            progress.draw(0, {}, force=True)
            progress.draw(0, {"192.0.2.1": "nmap"})
            progress.draw(0, {"192.0.2.1": "DNS"})
        self.assertEqual(len(messages.getvalue().splitlines()), 2)
        self.assertIn("nmap 0 DNS 1 | elapsed 6s", messages.getvalue())
        messages = io.StringIO()
        with redirect_stderr(messages), patch.object(messages, "isatty", return_value=True):
            progress = Progress(1)
            progress.draw(0, {}, force=True)
            progress.log("host stage")
            progress.draw(1, {}, force=True)
            progress.close()
        self.assertIn("\r", messages.getvalue())
        self.assertIn("host stage", messages.getvalue())
        self.assertTrue(messages.getvalue().endswith("\n"))

    def test_eta_uses_observed_throughput_and_includes_stalls(self):
        with patch("scan_ips.time.monotonic", return_value=0):
            progress = Progress(100)
        self.assertEqual(progress.estimate(0, 0), "estimating")
        self.assertEqual(progress.estimate(2, 2), "estimating")
        for done in range(1, 4):
            with patch("scan_ips.time.monotonic", return_value=done):
                progress.record(done)
        self.assertEqual(progress.estimate(3, 3), "~1m37s")
        self.assertEqual(progress.estimate(3, 6), "~3m14s")
        # Higher achieved concurrency/throughput shortens the estimate.
        self.assertEqual(progress.estimate(12, 3), "~22s")
        self.assertEqual(progress.estimate(100, 6), "0s")
        self.assertEqual(progress.estimate(3, 0), "estimating")

    def test_eta_adapts_to_recent_slowdown(self):
        with patch("scan_ips.time.monotonic", return_value=0):
            progress = Progress(200)
        for done in range(1, 65):
            with patch("scan_ips.time.monotonic", return_value=done):
                progress.record(done)
        self.assertEqual(progress.estimate(64, 64), "~2m16s")
        for done in range(65, 129):
            with patch("scan_ips.time.monotonic", return_value=64 + 2 * (done - 64)):
                progress.record(done)
        self.assertEqual(len(progress.samples), 65)
        self.assertEqual(progress.estimate(128, 192), "~2m24s")
        self.assertEqual(progress.estimate(128, 10000), "~3h06m")

    def test_out_of_order_completion_preserves_csv_order(self):
        release_first = threading.Event()
        messages = io.StringIO()
        real_log = Progress.log

        def scan(ip, *args):
            if str(ip) == "192.0.2.1":
                self.assertTrue(release_first.wait(2), "progress waited on the first host")
            return {"ip": str(ip), "status": "in_use"}

        def log(progress, message):
            if message.startswith("192.0.2.2: in_use"):
                release_first.set()
            real_log(progress, message)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scan.csv"
            with patch("scan_ips.shutil.which", return_value="nmap"), patch("scan_ips.scan_ip", side_effect=scan):
                with patch.object(Progress, "log", log), redirect_stderr(messages), redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["192.0.2.0/30", "-o", str(output), "-v"]), 0)
            with output.open(newline="") as stream:
                self.assertEqual([row["ip"] for row in csv.DictReader(stream)], ["192.0.2.1", "192.0.2.2"])
        self.assertLess(messages.getvalue().index("192.0.2.2: in_use"), messages.getvalue().index("192.0.2.1: in_use"))
        self.assertIn("2/2 (100%)", messages.getvalue())

    def test_real_local_tcp_connection(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            with patch("scan_ips.socket.gethostbyaddr", side_effect=socket.herror(1, "no PTR")):
                row = scan_ip("127.0.0.1", [listener.getsockname()[1]], 2)
        self.assertEqual(row["status"], "in_use", row)
        self.assertTrue(row["tcp_open"])


if __name__ == "__main__":
    unittest.main()
