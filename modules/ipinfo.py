import requests
import socket
import configparser
from pathlib import Path
import datetime


class Ipinfo:
    help = (
        "ipinfo: Query ipinfo.io for details about an IP address.\n"
        "Usage: ipinfo\n"
        "Supported target types: ip"
    )

    targets = ["ip"]

    def __init__(self):
        self.api_key = None
        self.load_api_key()

    def load_api_key(self):
        config_path = Path(__file__).parent / "ipinfo.conf"
        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)
            self.api_key = config.get("DEFAULT", "api_key", fallback=None)

    def run(self, target, args):
        url = f"https://ipinfo.io/{target}"
        if self.api_key:
            url += f"?token={self.api_key}"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            print("\033[92mIP Info:\033[0m")
            for k, v in data.items():
                print(f"  \033[93m{k.capitalize()}:\033[0m {v}")

            # ─── Graph Integration ────────────────────────────────
            if hasattr(self, "graph") and hasattr(self, "cli"):
                self.graph.add_node(target, type="ip")
                self.cli.log_graph(f"Added node: {target} (type=ip)")

                org = data.get("org")
                if org:
                    self.graph.add_node(org, type="org")
                    self.cli.log_graph(f"Added node: {org} (type=org)")
                    self.graph.add_edge(
                        target,
                        org,
                        label="org",
                        timestamp=datetime.datetime.now().isoformat(),
                    )
                    self.cli.log_graph(f"Added edge: {target} → {org} (label=org)")

                asn = data.get("asn")
                if asn:
                    asn_id = asn.get("asn")
                    if asn_id:
                        self.graph.add_node(asn_id, type="asn")
                        self.cli.log_graph(f"Added node: {asn_id} (type=asn)")
                        self.graph.add_edge(
                            target,
                            asn_id,
                            label="ASN",
                            timestamp=datetime.datetime.now().isoformat(),
                        )
                        self.cli.log_graph(
                            f"Added edge: {target} → {asn_id} (label=ASN)"
                        )

        except requests.exceptions.HTTPError as e:
            print(f"\033[91mHTTP Error:\033[0m {e}")
        except Exception as e:
            print(f"\033[91mError:\033[0m {e}")
