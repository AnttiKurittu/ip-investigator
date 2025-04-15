import requests
from urllib.parse import urlparse
import datetime


class Webrequest:
    help = (
        "webrequest: Scan for HTTP(S) services across common ports, follow redirects, and display headers and response size.\n"
        "Usage: webrequest\n"
        "Supported target types: IP, domain, URL"
    )

    targets = ["ip", "domain", "url"]

    COMMON_PORTS = [80, 443, 8080, 8443]
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36"

    def run(self, target, args):
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            host = parsed.hostname
        else:
            host = target

        print(f"\033[94mScanning HTTP/HTTPS services for {target}...\033[0m")

        for scheme in ["http", "https"]:
            for port in self.COMMON_PORTS:
                url = f"{scheme}://{host}:{port}"
                headers = {
                    "User-Agent": self.USER_AGENT,
                    "Host": host,  # always supply for IPs or domains
                }

                try:
                    response = requests.get(
                        url, headers=headers, allow_redirects=True, timeout=5
                    )

                    print(
                        f"\n\033[92m[+] {scheme.upper()} on port {port} responded:\033[0m"
                    )
                    print(f"\033[96mURL:\033[0m {response.url}")
                    print(f"\033[96mStatus:\033[0m {response.status_code}")
                    print(f"\033[96mHeaders:\033[0m")
                    for k, v in response.headers.items():
                        print(f"  {k}: {v}")
                    print(f"\033[96mBody Size:\033[0m {len(response.content)} bytes")

                    # Report redirect chain
                    if response.history:
                        print(f"\033[93mRedirect chain:\033[0m")
                        for step in response.history:
                            print(
                                f"  {step.status_code} → {step.headers.get('Location')}"
                            )

                    # Logging
                    if hasattr(self, "cli"):
                        self.cli.log(f"[webrequest] Response from {url}")
                        self.cli.log(f"[webrequest] Status: {response.status_code}")
                        self.cli.log(f"[webrequest] Final URL: {response.url}")
                        for k, v in response.headers.items():
                            self.cli.log(f"[webrequest] Header: {k}: {v}")
                        self.cli.log(
                            f"[webrequest] Body size: {len(response.content)} bytes"
                        )
                        if response.history:
                            for step in response.history:
                                self.cli.log(
                                    f"[webrequest] Redirect: {step.status_code} → {step.headers.get('Location')}"
                                )

                    # Graph
                    if hasattr(self, "graph"):
                        node_label = f"{scheme}://{host}:{port}"
                        self.graph.add_node(node_label, type="web")
                        self.graph.add_edge(
                            target,
                            node_label,
                            label=f"{scheme.upper()} {response.status_code}",
                            timestamp=datetime.datetime.now().isoformat(),
                        )
                        if hasattr(self, "cli"):
                            self.cli.log_graph(f"Added node: {node_label} (type=web)")
                            self.cli.log_graph(
                                f"Added edge: {target} → {node_label} (label={scheme.upper()} {response.status_code})"
                            )

                except requests.exceptions.ConnectionError:
                    continue
                except requests.exceptions.RequestException as e:
                    print(f"\033[91m[-] {url} failed:\033[0m {e}")
                    if hasattr(self, "cli"):
                        self.cli.log(f"[webrequest] Request failed for {url}: {e}")
