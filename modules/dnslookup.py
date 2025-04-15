import socket
import dns.resolver
import dns.reversename
from urllib.parse import urlparse
from datetime import datetime


class Dnslookup:
    help = (
        "dnslookup: Perform DNS lookups on domains or reverse lookups on IPs.\n"
        "Usage: dnslookup\n"
        "Supported target types: IP, domain"
    )

    targets = ["ip", "domain"]

    def __init__(self):
        self.primary_resolver = dns.resolver.Resolver(configure=False)
        self.primary_resolver.nameservers = [
            "1.1.1.1",
            "8.8.8.8",
        ]  # Cloudflare & Google
        self.fallback_resolver = dns.resolver.Resolver()  # Use system DNS config

    def run(self, target, args):
        if target.startswith("http"):
            domain = urlparse(target).hostname
            print(
                f"\033[93mNote:\033[0m Extracted domain '{domain}' from URL '{target}'."
            )
            target = domain

        if self.is_ip(target):
            self.reverse_dns(target)
        else:
            self.forward_dns(target)

    def is_ip(self, value):
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            return False

    def reverse_dns(self, ip):
        print(f"\033[94mReverse DNS lookup for {ip}\033[0m")
        try:
            reversed_dns = socket.gethostbyaddr(ip)
            hostname = reversed_dns[0]
            print(f"\033[93mHostname:\033[0m {hostname}")

            # ─── Graph ─────────────────────────────
            if hasattr(self, "graph") and hasattr(self, "cli"):
                self.graph.add_node(ip, type="ip")
                self.graph.add_node(hostname, type="domain")
                self.graph.add_edge(
                    ip,
                    hostname,
                    label="reverse_dns",
                    timestamp=datetime.now().isoformat(),
                )
                self.cli.log_graph(f"Added node: {ip} (type=ip)")
                self.cli.log_graph(f"Added node: {hostname} (type=domain)")
                self.cli.log_graph(f"Added edge: {ip} → {hostname} (label=reverse_dns)")

        except socket.herror:
            print("\033[91mError:\033[0m No reverse DNS entry found.")

    def forward_dns(self, domain):
        print(f"\033[94mDNS records for {domain}\033[0m")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for rtype in record_types:
            for resolver, label in [
                (self.primary_resolver, "Primary"),
                (self.fallback_resolver, "Fallback"),
            ]:
                try:
                    answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                    if answers.rrset:
                        print(f"\033[93m{rtype} Records ({label}):\033[0m")
                        for rdata in answers:
                            val = rdata.to_text()
                            print(f"  {val}")

                            # ─── Skip TXT from graph ────────
                            if rtype == "TXT":
                                continue

                            # ─── Graph ───────────────────────
                            if hasattr(self, "graph") and hasattr(self, "cli"):
                                self.graph.add_node(domain, type="domain")
                                self.cli.log_graph(
                                    f"Added node: {domain} (type=domain)"
                                )

                                if rtype in ["A", "AAAA"]:
                                    self.graph.add_node(val, type="ip")
                                else:
                                    self.graph.add_node(val, type=rtype.lower())

                                self.graph.add_edge(
                                    domain,
                                    val,
                                    label=rtype,
                                    timestamp=datetime.now().isoformat(),
                                )
                                self.cli.log_graph(
                                    f"Added node: {val} (type={rtype.lower()})"
                                )
                                self.cli.log_graph(
                                    f"Added edge: {domain} → {val} (label={rtype})"
                                )

                        break  # success, don't fall back
                except dns.resolver.NoNameservers:
                    continue
                except dns.resolver.NXDOMAIN:
                    print("\033[91mError:\033[0m Domain does not exist.")
                    return
                except Exception:
                    continue
            else:
                print(
                    f"\033[91mError:\033[0m Could not retrieve {rtype} records from any resolver."
                )
