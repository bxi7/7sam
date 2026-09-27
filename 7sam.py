#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import html
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
PAGE = ROOT / "7sam.html"
COMMON_PORTS = [20, 21, 22, 23, 25, 53, 67, 68, 80, 81, 110, 123, 135, 139,
                143, 443, 445, 465, 500, 515, 548, 554, 587, 631, 993, 995,
                1433, 1883, 3306, 3389, 5000, 5353, 5432, 5900, 5985, 6379,
                8000, 8008, 8080, 8443, 8888, 9000, 9100, 9200, 27017]
SCAN_LOCK = threading.Lock()
SCAN_STATE = {"running": False, "progress": "", "result": None, "error": None}


def run_command(args: list[str], timeout: float = 3) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, errors="replace",
                              timeout=timeout, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def local_ipv4() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = item[4][0]
            if not ip.startswith("127."):
                return ip
    finally:
        sock.close()
    raise RuntimeError("Could not determine the local IP address. Connect to a network and try again.")


def network_details() -> dict:
    ip = local_ipv4()
    system = platform.system().lower()
    prefix = None
    gateway = "Unknown"
    if system == "windows":
        output = run_command(["ipconfig", "/all"])
        blocks = re.split(r"\r?\n\s*\r?\n", output)
        for block in blocks:
            if ip not in block:
                continue
            mask = re.search(r"Subnet Mask[^:\n]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", block, re.I)
            gate = re.search(r"Default Gateway[^:\n]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", block, re.I)
            if mask:
                try:
                    prefix = ipaddress.IPv4Network("0.0.0.0/" + mask.group(1)).prefixlen
                except ValueError:
                    pass
            if gate:
                gateway = gate.group(1)
            break
    else:
        output = run_command(["ip", "-o", "-f", "inet", "addr", "show"])
        for line in output.splitlines():
            if re.search(r"\binet\s+" + re.escape(ip) + r"/(\d+)", line):
                match = re.search(r"\binet\s+" + re.escape(ip) + r"/(\d+)", line)
                prefix = int(match.group(1)) if match else None
                break
        route = run_command(["ip", "route", "show", "default"])
        match = re.search(r"\bvia\s+(\d{1,3}(?:\.\d{1,3}){3})", route)
        if match:
            gateway = match.group(1)
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix or 24}", strict=False)
    except ValueError:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return {"local_ip": ip, "network": str(network), "gateway": gateway,
            "hostname": socket.gethostname(), "platform": platform.system()}


def neighbor_table() -> dict[str, str]:
    if platform.system().lower() == "windows":
        output = run_command(["arp", "-a"])
        pairs = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([\da-f]{2}(?:-[\da-f]{2}){5})\s+\w+", output, re.I)
    else:
        output = run_command(["ip", "neigh", "show"])
        pairs = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}).*?\blladdr\s+([\da-f]{2}(?::[\da-f]{2}){5})", output, re.I)
    return {ip: mac.replace("-", ":").upper() for ip, mac in pairs}


def ping_host(ip: str) -> str | None:
    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", "400", ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(command, capture_output=True, timeout=2, check=False)
        return ip if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def hostname_for(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except (OSError, socket.herror):
        return "Unknown"


def local_mac() -> str:
    value = uuid.getnode()
    return ":".join(f"{(value >> shift) & 255:02X}" for shift in range(40, -1, -8))


def scan_ports(ip: str, ports: list[int], timeout: float = 0.35) -> list[int]:
    opened: list[int] = []
    def check(port: int) -> int | None:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return port
        except OSError:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(80, len(ports) or 1)) as pool:
        for result in pool.map(check, ports):
            if result is not None:
                opened.append(result)
    return sorted(opened)


def scan_network(network_text: str | None = None, ports: list[int] | None = None,
                 progress=None) -> dict:
    info = network_details()
    network = ipaddress.ip_network(network_text or info["network"], strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("7sam currently supports IPv4 networks only.")
    if network.num_addresses > 4096:
        raise ValueError("The range exceeds 4096 addresses. Choose a smaller range, such as /24 or /20.")
    if ipaddress.ip_address(info["local_ip"]) not in network:
        raise ValueError("This device's IP is outside the selected range. Enter your local network range.")
    ports = sorted(set(ports or COMMON_PORTS))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Port numbers must be between 1 and 65535.")
    if progress:
        progress(f"Discovering devices on {network}…")
    known = neighbor_table()
    hosts = {ip for ip in known if ipaddress.ip_address(ip) in network}
    targets = [str(host) for host in network.hosts() if str(host) != info["local_ip"]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as pool:
        for found in pool.map(ping_host, targets):
            if found:
                hosts.add(found)
    known.update(neighbor_table())
    hosts.add(info["local_ip"])
    rows = []
    sorted_hosts = sorted(hosts, key=lambda value: int(ipaddress.ip_address(value)))
    for index, ip in enumerate(sorted_hosts, 1):
        if progress:
            progress(f"Scanning ports on device {index} of {len(sorted_hosts)}…")
        rows.append({"ip": ip, "mac": known.get(ip, local_mac() if ip == info["local_ip"] else "Unavailable"),
                     "name": info["hostname"] if ip == info["local_ip"] else hostname_for(ip),
                     "local": ip == info["local_ip"], "ports": scan_ports(ip, ports)})
    return {**info, "network": str(network), "port_count": len(ports),
            "checked_ports": ports, "devices": rows,
            "open_port_count": sum(len(device["ports"]) for device in rows),
            "finished_at": time.strftime("%H:%M:%S")}


def parse_ports(value: str) -> list[int]:
    if value.strip().lower() == "common":
        return COMMON_PORTS
    if value.strip().lower() == "all":
        return list(range(1, 65536))
    try:
        ports = [int(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Enter comma-separated ports, such as 22,80,443, or use 'common'.") from exc
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError("Port numbers must be between 1 and 65535.")
    return sorted(set(ports))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[7sam] {self.address_string()} - {fmt % args}")

    def send_json(self, value, status=200):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlparse(self.path).path
        if route == "/api/info":
            try:
                self.send_json(network_details())
            except Exception as exc:
                self.send_json({"error": str(exc)}, 500)
        elif route == "/api/status":
            with SCAN_LOCK:
                self.send_json({"running": SCAN_STATE["running"], "progress": SCAN_STATE["progress"],
                                "result": SCAN_STATE["result"], "error": SCAN_STATE["error"]})
        elif route == "/" or route == "/7sam.html":
            try:
                body = PAGE.read_text(encoding="utf-8").replace("__LANGUAGE__", self.server.language).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                self.send_error(404, "Place 7sam.html next to 7sam.py.")
        else:
            self.send_error(404)

    def do_POST(self):
        if urlparse(self.path).path != "/api/scan":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length > 4096:
            self.send_json({"error": "Request is too large."}, 413)
            return
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            network_text = str(data.get("network", "")).strip() or None
            network = ipaddress.ip_network(network_text, strict=False) if network_text else None
            if network_text and (not isinstance(network, ipaddress.IPv4Network) or network.num_addresses > 4096):
                raise ValueError("Enter an IPv4 range with no more than 4096 addresses.")
            port_list = parse_ports(str(data.get("ports", "common")))
            if len(port_list) > 256:
                raise ValueError("The web interface accepts up to 256 ports per scan.")
            with SCAN_LOCK:
                if SCAN_STATE["running"]:
                    self.send_json({"error": "A scan is already running."}, 409)
                    return
                SCAN_STATE.update(running=True, progress="Starting scan…", error=None, result=None)
            threading.Thread(target=self.run_scan, args=(network_text, port_list), daemon=True).start()
            self.send_json({"started": True}, 202)
        except (ValueError, json.JSONDecodeError, argparse.ArgumentTypeError) as exc:
            self.send_json({"error": str(exc)}, 400)

    @staticmethod
    def run_scan(network_text, ports):
        def progress(message):
            with SCAN_LOCK:
                SCAN_STATE["progress"] = message
        try:
            result = scan_network(network_text, ports, progress)
            with SCAN_LOCK:
                SCAN_STATE.update(running=False, progress="Scan complete", result=result, error=None)
        except Exception as exc:
            with SCAN_LOCK:
                SCAN_STATE.update(running=False, progress="", error=str(exc))


def run_cli(network_text: str | None, ports: list[int], language: str):
    labels = ({"title": "7sam — ماسح الشبكة المحلية", "warning": "افحص الشبكات التي تملكها أو لديك إذن بفحصها فقط.",
               "local_ip": "عنوان IP المحلي", "network": "الشبكة", "gateway": "البوابة", "devices": "الأجهزة المكتشفة",
               "ports": "المنافذ المفحوصة", "open": "المنافذ المفتوحة", "none": "لا توجد منافذ مفتوحة ظاهرة"}
              if language == "ar" else
              {"title": "7sam — Local Network Scanner", "warning": "Only scan networks you own or are authorized to assess.",
               "local_ip": "Local IP", "network": "Network", "gateway": "Gateway", "devices": "Devices found",
               "ports": "Ports checked", "open": "Open ports", "none": "No open ports detected"})
    print(labels["title"])
    print(labels["warning"] + "\n")
    result = scan_network(network_text, ports, lambda text: print("• " + text))
    print(f"\n{labels['local_ip']:<16}: {result['local_ip']}")
    print(f"{labels['network']:<16}: {result['network']}")
    print(f"{labels['gateway']:<16}: {result['gateway']}")
    print(f"{labels['devices']:<16}: {len(result['devices'])}")
    print(f"{labels['ports']:<16}: {result['port_count']}\n")
    for device in result["devices"]:
        ports_text = ", ".join(map(str, device["ports"])) or labels["none"]
        print(f"{device['name']}  |  IP: {device['ip']}  |  MAC: {device['mac']}  |  {labels['open']} ({len(device['ports'])}): {ports_text}")


def main():
    parser = argparse.ArgumentParser(description="7sam: simple local network scanner")
    parser.add_argument("--scan", action="store_true", help="Scan from the terminal instead of opening the web interface")
    parser.add_argument("--network", help="IPv4 CIDR range, such as 192.168.1.0/24")
    parser.add_argument("--ports", type=parse_ports, default=COMMON_PORTS,
                        help="common, all, or a list such as 22,80,443")
    parser.add_argument("--language", choices=("en", "ar"), default="en",
                        help="Interface language: en or ar (default: en)")
    parser.add_argument("--host", default="127.0.0.1", help="Web interface bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8765, help="Web interface port (default: 8765)")
    args = parser.parse_args()
    if args.scan:
        try:
            run_cli(args.network, args.ports, args.language)
        except (ValueError, RuntimeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.language = args.language
    print("7sam is ready. Open: http://%s:%d" % (args.host, args.port))
    print("Press Ctrl+C to stop. Only scan networks you own or are authorized to assess.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n7sam stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
