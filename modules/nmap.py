import subprocess
import datetime
from urllib.parse import urlparse


class Nmap:
    help = (
        "nmap: Scan the target IP for common open ports and identify services.\n"
        "Usage: nmap\n"
        "Supported target types: IP"
    )

    targets = ["ip"]

    def run(self, target, args):
        original_target = target

        if target.startswith("http"):
            print("\033[91mError:\033[0m This module only supports IP addresses.")
            return

        print(f"\033[94mRunning Nmap on {target}...\033[0m")

        # 15 common ports
        common_ports = [
            "22",
            "80",
            "443",
            "21",
            "25",
            "110",
            "143",
            "53",
            "3306",
            "3389",
            "8080",
            "445",
            "139",
            "111",
            "995",
        ]
        port_list = ",".join(common_ports)

        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-p", port_list, target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output = result.stdout.decode("utf-8", errors="replace")
            print()
            print("\033[94mNmap Results:\033[0m\n")
            parsing_ports = False
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("PORT"):
                    parsing_ports = True
                    print(f"\033[96m{line}\033[0m")  # header line
                    continue
                if parsing_ports:
                    if not line:
                        parsing_ports = False
                        print()
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]
                        state = parts[1]
                        service = parts[2]

                        color = "\033[97m"  # default white
                        if state == "open":
                            color = "\033[92m"  # green
                        elif state == "closed":
                            color = "\033[91m"  # red
                        elif state == "filtered":
                            color = "\033[93m"  # yellow

                        print(
                            f"{color}{port_proto:<10} {state:<10} {service:<15}\033[0m"
                        )

        except FileNotFoundError:
            print(
                "\033[91mError:\033[0m The 'nmap' command is not available on this system."
            )
            return
        except Exception as e:
            print(f"\033[91mError:\033[0m Failed to run nmap: {e}")
            return

        # Log the results
        if hasattr(self, "cli"):
            self.cli.log(f"[nmap] {output}")

        # ─── Graph integration ────────────────────────────────
        if hasattr(self, "graph"):
            self.graph.add_node(target, type="ip")
            self.graph.add_node("nmap", type="tool")
            self.graph.add_edge(
                target,
                "nmap",
                label="nmap",
                timestamp=datetime.datetime.now().isoformat(),
            )

            # Extract open ports from Nmap output
            parsing_ports = False
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("PORT"):
                    parsing_ports = True
                    continue
                if parsing_ports:
                    if not line:
                        parsing_ports = False
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]  # e.g. 80/tcp
                        state = parts[1]  # e.g. open
                        service = parts[2]  # e.g. http
                        if state == "open":
                            port_node = f"port:{port_proto}/{service}"
                            self.graph.add_node(port_node, type="port")
                            self.graph.add_edge(
                                target,
                                port_node,
                                label="open",
                                timestamp=datetime.datetime.now().isoformat(),
                            )
                            if hasattr(self, "cli"):
                                self.cli.log_graph(
                                    f"Added node: {port_node} (type=port)"
                                )
                                self.cli.log_graph(
                                    f"Added edge: {target} → {port_node} (label=open)"
                                )
