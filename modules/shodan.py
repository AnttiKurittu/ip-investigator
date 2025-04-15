import socket
import requests
import configparser
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime


class Shodan:
    help = (
        "shodan: Query Shodan for info about an IP address (or domain → IP).\n"
        "Usage: shodan\n"
        "Supported target types: ip, domain, url\n"
        "Requires: Shodan API key in modules/shodan.conf"
    )

    targets = ["ip", "domain", "url"]

    def __init__(self):
        self.api_key = None
        self.load_api_key()

    def load_api_key(self):
        config_path = Path(__file__).parent / "shodan.conf"
        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)
            self.api_key = config.get("DEFAULT", "api_key", fallback=None)

    def resolve_domain_to_ip(self, domain):
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            if not ips:
                print("\033[91mError:\033[0m No A records found.")
                return None
            if len(ips) > 1:
                print(f"\033[93mNote:\033[0m Multiple IPs found. Using first: {ips[0]}")
            return ips[0]
        except Exception as e:
            print(f"\033[91mError:\033[0m DNS resolution failed: {e}")
            return None

    def run(self, target, args):
        if not self.api_key:
            print("\033[91mError:\033[0m Shodan API key not found in shodan.conf.")
            return

        original = target

        if target.startswith("http"):
            parsed = urlparse(target)
            domain = parsed.hostname
            print(
                f"\033[93mNote:\033[0m Extracted domain '{domain}' from URL '{target}'."
            )
            target = domain

        if not self.is_ip(target):
            resolved_ip = self.resolve_domain_to_ip(target)
            if not resolved_ip:
                return
            print(f"\033[93mNote:\033[0m Using resolved IP: {resolved_ip}")
            target = resolved_ip

        print(f"\033[94mQuerying Shodan for IP:\033[0m {target}")
        try:
            url = f"https://api.shodan.io/shodan/host/{target}?key={self.api_key}"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            print("\n\033[92mGeneral Information:\033[0m")
            print(f"  \033[93mIP:\033[0m {data.get('ip_str', 'N/A')}")
            print(f"  \033[93mHostnames:\033[0m")
            for h in data.get("hostnames", []):
                print(f"    - {h}")
            print(f"  \033[93mOrganization:\033[0m {data.get('org', 'N/A')}")
            print(f"  \033[93mOperating System:\033[0m {data.get('os', 'Unknown')}")
            print(
                f"  \033[93mCity:\033[0m {data.get('city', 'N/A')}, {data.get('country_name', 'N/A')}"
            )
            print(f"  \033[93mISP:\033[0m {data.get('isp', 'N/A')}")
            print(f"  \033[93mASN:\033[0m {data.get('asn', 'N/A')}")

            if ports := data.get("ports"):
                print(f"\n\033[92mOpen Ports:\033[0m")
                for port in sorted(ports):
                    print(f"  - {port}")

            if services := data.get("data"):
                print("\n\033[92mDetected Services:\033[0m")
                for svc in services:
                    port = svc.get("port")
                    banner = (
                        svc.get("product")
                        or svc.get("http", {}).get("title")
                        or "Unknown service"
                    )
                    print(f"  \033[93mPort {port}:\033[0m {banner}")

            # ─── Graph Integration ────────────────────────────────
            if hasattr(self, "graph") and hasattr(self, "cli"):
                ip = data.get("ip_str", target)
                self.graph.add_node(ip, type="ip")
                self.cli.log_graph(f"Added node: {ip} (type=ip)")

                # Hostnames
                for h in data.get("hostnames", []):
                    self.graph.add_node(h, type="hostname")
                    self.graph.add_edge(
                        ip, h, label="hostname", timestamp=datetime.now().isoformat()
                    )
                    self.cli.log_graph(f"Added node: {h} (type=hostname)")
                    self.cli.log_graph(f"Added edge: {ip} → {h} (label=hostname)")

                # Ports
                for port in data.get("ports", []):
                    port_node = f"port_{port}"
                    self.graph.add_node(port_node, type="port")
                    self.graph.add_edge(
                        ip,
                        port_node,
                        label="port",
                        timestamp=datetime.now().isoformat(),
                    )
                    self.cli.log_graph(f"Added node: {port_node} (type=port)")
                    self.cli.log_graph(f"Added edge: {ip} → {port_node} (label=port)")

                # Services
                for svc in data.get("data", []):
                    port = svc.get("port")
                    service = svc.get("product") or svc.get("http", {}).get("title")
                    if service:
                        svc_node = f"svc_{port}_{service}"
                        self.graph.add_node(svc_node, type="service")
                        self.graph.add_edge(
                            ip,
                            svc_node,
                            label="service",
                            timestamp=datetime.now().isoformat(),
                        )
                        self.cli.log_graph(f"Added node: {svc_node} (type=service)")
                        self.cli.log_graph(
                            f"Added edge: {ip} → {svc_node} (label=service)"
                        )

                # Org and ASN
                org = data.get("org")
                if org:
                    self.graph.add_node(org, type="org")
                    self.graph.add_edge(
                        ip, org, label="org", timestamp=datetime.now().isoformat()
                    )
                    self.cli.log_graph(f"Added node: {org} (type=org)")
                    self.cli.log_graph(f"Added edge: {ip} → {org} (label=org)")

                asn = data.get("asn")
                if asn:
                    self.graph.add_node(asn, type="asn")
                    self.graph.add_edge(
                        ip, asn, label="asn", timestamp=datetime.now().isoformat()
                    )
                    self.cli.log_graph(f"Added node: {asn} (type=asn)")
                    self.cli.log_graph(f"Added edge: {ip} → {asn} (label=asn)")

        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                print(f"\033[93mNo Shodan data found for {target}.\033[0m")
            else:
                print(f"\033[91mHTTP Error:\033[0m {e}")
                print(f"\033[90mResponse:\033[0m {response.text}")
        except Exception as e:
            print(f"\033[91mError:\033[0m {e}")

    def is_ip(self, value):
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            return False
