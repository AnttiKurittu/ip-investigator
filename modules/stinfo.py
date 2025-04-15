import requests
import configparser
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime


class Stinfo:
    help = (
        "stinfo: Query SecurityTrails for current DNS and infrastructure data for a domain.\n"
        "Usage: stinfo\n"
        "Supported target types: domain"
    )

    targets = ["domain"]

    def __init__(self):
        self.api_key = None
        self.load_api_key()

    def load_api_key(self):
        config_path = Path(__file__).parent / "stinfo.conf"
        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)
            self.api_key = config.get("DEFAULT", "api_key", fallback=None)

    def run(self, target, args):
        if not self.api_key:
            print(
                "\033[91mError:\033[0m SecurityTrails API key not found in stinfo.conf."
            )
            return

        if target.startswith("http"):
            domain = urlparse(target).hostname
            print(
                f"\033[93mNote:\033[0m Extracted domain '{domain}' from URL '{target}'."
            )
            target = domain

        print(f"Querying SecurityTrails for domain: \033[96m{target}\033[0m")
        url = f"https://api.securitytrails.com/v1/domain/{target}"
        headers = {"apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"\033[91mError:\033[0m {e}")
            return

        current_dns = data.get("current_dns", {})
        if not current_dns:
            print("No current DNS records found.")
            return

        def print_records(title, records, key):
            if records:
                print(f"\033[92m{title}:\033[0m")
                for entry in records:
                    value = entry.get(key) or entry.get("value") or entry.get("email")
                    if value:
                        print(f"  - {value}")
                        # Skip graphing TXT records
                        if title == "TXT":
                            continue
                        # Graph node/edge
                        if hasattr(self, "graph") and hasattr(self, "cli"):
                            self.graph.add_node(value, type=title.lower())
                            self.cli.log_graph(
                                f"Added node: {value} (type={title.lower()})"
                            )
                            self.graph.add_edge(
                                target,
                                value,
                                label=title,
                                timestamp=datetime.now().isoformat(),
                            )
                            self.cli.log_graph(
                                f"Added edge: {target} → {value} (label={title})"
                            )

        print("\n\033[94mDNS Records:\033[0m")

        # A
        print_records("A", current_dns.get("a", {}).get("values", []), "ip")

        # AAAA
        print_records("AAAA", current_dns.get("aaaa", {}).get("values", []), "ipv6")

        # MX
        print_records("MX", current_dns.get("mx", {}).get("values", []), "hostname")

        # NS
        print_records("NS", current_dns.get("ns", {}).get("values", []), "nameserver")

        # TXT (printed only, skipped from graph)
        print_records("TXT", current_dns.get("txt", {}).get("values", []), "value")

        # CNAME
        print_records("CNAME", current_dns.get("cname", {}).get("values", []), "value")

        # SOA
        print_records("SOA", current_dns.get("soa", {}).get("values", []), "email")

        # ─── Graph node for target ─────────────────────────────
        if hasattr(self, "graph") and hasattr(self, "cli"):
            self.graph.add_node(target, type="domain")
            self.cli.log_graph(f"Added node: {target} (type=domain)")
