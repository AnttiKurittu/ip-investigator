import platform
import subprocess
import datetime
from urllib.parse import urlparse


class Ping:
    help = (
        "ping: Send 3 ICMP packets to the target and return the response.\n"
        "Usage: ping\n"
        "Supported target types: IP, domain"
    )

    targets = ["ip", "domain"]

    def run(self, target, args):
        original_target = target
        if target.startswith("http"):
            domain = urlparse(target).hostname
            print(
                f"\033[93mNote:\033[0m Extracted domain '{domain}' from URL '{target}' for pinging."
            )
            target = domain

        print(f"Pinging {target} with 3 packets...\n")
        count_flag = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", count_flag, "3", target],
                capture_output=True,
                text=True,
                check=True,
            )
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print("Ping failed:", e)
        except FileNotFoundError:
            print(
                "The 'ping' command is not available on this system. Please install it to use this module."
            )

        # ─── Graph integration ────────────────────────────────
        if hasattr(self, "graph"):
            self.graph.add_node(target, type="ip_or_domain")
            self.graph.add_node("ping", type="tool")
            self.graph.add_edge(
                target,
                "ping",
                label="ping",
                timestamp=datetime.datetime.now().isoformat(),
            )
