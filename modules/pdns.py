import requests
import socket
from datetime import datetime
from urllib.parse import urlparse


class Pdns:
    help = (
        "pdns: Query Mnemonic Passive DNS for historical resolutions.\n"
        "Usage: pdns [offset]\n"
        "Supported target types: ip, domain"
    )

    targets = ["ip", "domain"]

    def run(self, target, args):
        offset = 0
        if args and args[0].isdigit():
            offset = int(args[0])

        if target.startswith("http"):
            parsed = urlparse(target)
            domain = parsed.hostname
            print(f"\033[93mNote:\033[0m Extracted domain '{domain}' from URL.")
            target = domain

        print(f"Querying Mnemonic Passive DNS for target: \033[96m{target}\033[0m")
        url = f"https://api.mnemonic.no/pdns/v3/{target}?offset={offset}"

        try:
            response = requests.get(url, timeout=300)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"\033[91mError:\033[0m Failed to contact Mnemonic PDNS API: {e}")
            return

        records = data.get("data", [])
        count = len(records)

        if not records:
            print("\033[93mNo passive DNS records found.\033[0m")
            return

        if offset:
            print(f"\033[94mSkipping first {offset} records.\033[0m")

        print(f"\033[92mFound {count} record(s):\033[0m\n")
        for record in records:
            rrtype = record.get("rrtype")
            query = record.get("query")
            answer = record.get("answer")
            first_seen = datetime.utcfromtimestamp(
                record["firstSeenTimestamp"] / 1000
            ).strftime("%Y-%m-%d")
            last_seen = datetime.utcfromtimestamp(
                record["lastSeenTimestamp"] / 1000
            ).strftime("%Y-%m-%d")

            print(f"\033[93m{query} → {answer} [{rrtype}]\033[0m")
            print(f"  First seen: {first_seen}")
            print(f"  Last seen:  {last_seen}\n")

            # ─── Graph Integration ─────────────────────────────
            if hasattr(self, "graph") and hasattr(self, "cli"):
                # Determine direction
                if self.is_ip(target):  # IP → domain
                    self.graph.add_node(target, type="ip")
                    self.graph.add_node(query, type="domain")
                    self.graph.add_edge(
                        target,
                        query,
                        label="pdns",
                        timestamp=datetime.now().isoformat(),
                    )
                    self.cli.log_graph(f"Added node: {target} (type=ip)")
                    self.cli.log_graph(f"Added node: {query} (type=domain)")
                    self.cli.log_graph(f"Added edge: {target} → {query} (label=pdns)")
                else:  # domain → IP
                    self.graph.add_node(target, type="domain")
                    self.graph.add_node(answer, type="ip")
                    self.graph.add_edge(
                        target,
                        answer,
                        label="pdns",
                        timestamp=datetime.now().isoformat(),
                    )
                    self.cli.log_graph(f"Added node: {target} (type=domain)")
                    self.cli.log_graph(f"Added node: {answer} (type=ip)")
                    self.cli.log_graph(f"Added edge: {target} → {answer} (label=pdns)")

    def is_ip(self, value):
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            return False
