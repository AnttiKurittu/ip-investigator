import subprocess
import datetime
import re
from urllib.parse import urlparse


class Whois:
    help = (
        "whois: Perform a WHOIS lookup on the target IP or domain.\n"
        "Usage: whois\n"
        "Supported target types: ip, domain"
    )

    targets = ["ip", "domain"]

    def run(self, target, args):
        if target.startswith("http"):
            domain = urlparse(target).hostname
            print(
                f"\033[93mNote:\033[0m Extracted domain '{domain}' from URL '{target}'."
            )
            target = domain

        print(f"Performing WHOIS lookup for {target}...\n")
        try:
            result = subprocess.run(
                ["whois", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output = result.stdout.decode("utf-8", errors="replace")
            print(output)
        except subprocess.CalledProcessError as e:
            print("WHOIS lookup failed:", e)
            return
        except FileNotFoundError:
            print(
                "The 'whois' command is not available on this system. Please install it to use this module."
            )
            return

        # ─── Graph Integration ────────────────────────────────
        if hasattr(self, "graph") and hasattr(self, "cli"):
            self.graph.add_node(target, type="ip_or_domain")
            self.cli.log_graph(f"Added node: {target} (type=ip_or_domain)")

            self.graph.add_node("whois", type="tool")
            self.cli.log_graph("Added node: whois (type=tool)")

            self.graph.add_edge(
                target,
                "whois",
                label="whois",
                timestamp=datetime.datetime.now().isoformat(),
            )
            self.cli.log_graph(f"Added edge: {target} → whois (label=whois)")

            # ─── Parse Key WHOIS Fields ─────────────────────
            field_patterns = {
                "organisation": r"(?i)^org(?:anization)?(?: name)?:\s*(.+)",
                "email": r"(?i)^e-?mail:\s*(.+)",
                "status": r"(?i)^status:\s*(.+)",
                "created": r"(?i)^created:\s*(.+)",
                "changed": r"(?i)^changed:\s*(.+)",
            }

            for field, pattern in field_patterns.items():
                matches = re.findall(pattern, output, re.MULTILINE)
                for match in matches:
                    value = match.strip()
                    node_id = f"{field}:{value}"
                    self.graph.add_node(node_id, type=field)
                    self.graph.add_edge(
                        target,
                        node_id,
                        label="whois",
                        timestamp=datetime.datetime.now().isoformat(),
                    )
                    self.cli.log_graph(f"Added node: {node_id} (type={field})")
                    self.cli.log_graph(
                        f"Added edge: {target} → {node_id} (label=whois)"
                    )
