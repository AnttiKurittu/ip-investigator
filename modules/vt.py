import requests
import configparser
import re
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime


class Vt:
    help = (
        "vt: Query VirusTotal for IP, domain, or URL information.\n"
        "Usage: vt\n"
        "Supported target types: ip, domain, url"
    )

    targets = ["ip", "domain", "url"]

    def __init__(self):
        self.api_key = None
        self.load_api_key()

    def load_api_key(self):
        config_path = Path(__file__).parent / "vt.conf"
        if config_path.exists():
            config = configparser.ConfigParser()
            config.read(config_path)
            self.api_key = config.get("DEFAULT", "api_key", fallback=None)

    def run(self, target, args):
        if not self.api_key:
            print("\033[91mError:\033[0m VirusTotal API key not found in vt.conf.")
            return

        # Normalize domain from URL if needed
        if target.startswith("http"):
            parsed = urlparse(target)
            print(
                f"\033[93mNote:\033[0m Extracted domain '{parsed.hostname}' from URL."
            )
            target = parsed.hostname

        self.query_virustotal(target)

    def query_virustotal(self, target):
        base_url = "https://www.virustotal.com/api/v3"
        headers = {"x-apikey": self.api_key}
        target_type = self.classify_target(target)

        endpoint_map = {
            "ip": f"/ip_addresses/{target}",
            "domain": f"/domains/{target}",
            "url": "/urls",
        }

        if target_type not in endpoint_map:
            print(f"\033[91mError:\033[0m Unsupported target type: {target_type}")
            return

        try:
            if target_type == "url":
                # For URLs, first submit it to get its analysis ID
                response = requests.post(
                    f"{base_url}/urls",
                    headers=headers,
                    data={"url": target},
                    timeout=15,
                )
                response.raise_for_status()
                analysis_id = response.json()["data"]["id"]
                endpoint = f"/urls/{analysis_id}"
            else:
                endpoint = endpoint_map[target_type]

            url = f"{base_url}{endpoint}"
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"\033[91mError:\033[0m API request failed: {e}")
            return

        print(f"\033[94mVirusTotal results for {target} ({target_type}):\033[0m\n")
        attributes = data.get("data", {}).get("attributes", {})

        # General metadata
        fields = [
            ("Reputation", attributes.get("reputation")),
            ("Last Analysis Stats", attributes.get("last_analysis_stats")),
            ("Categories", attributes.get("categories")),
            ("Tags", attributes.get("tags")),
            ("ASN", attributes.get("asn")),
            ("ISP", attributes.get("isp")),
            ("Country", attributes.get("country")),
        ]

        for label, value in fields:
            if value:
                print(f"\033[93m{label}:\033[0m {value}")
                if hasattr(self, "cli"):
                    self.cli.log(f"[vt] {label}: {value}")

        # Last analysis results
        engines = attributes.get("last_analysis_results", {})
        filtered_results = []

        for engine, result in engines.items():
            category = result.get("category", "")
            if category not in ("harmless", "undetected"):
                filtered_results.append((engine, category))

        if filtered_results:
            print(f"\n\033[92mLast Analysis Results (Filtered):\033[0m")
            for engine, category in filtered_results:
                # Color-code categories
                if category == "malicious":
                    color = "\033[91m"  # red
                elif category == "suspicious":
                    color = "\033[93m"  # yellow
                elif category == "phishing":
                    color = "\033[95m"  # magenta
                else:
                    color = "\033[90m"  # gray

                print(f"  {color}{engine}: {category}\033[0m")
                if hasattr(self, "cli"):
                    self.cli.log(f"[vt] {engine}: {category}")

        # Graph integration
        if hasattr(self, "graph"):
            self.graph.add_node(target, type=target_type)
            self.graph.add_node("virustotal", type="tool")
            self.graph.add_edge(
                target,
                "virustotal",
                label="vt_query",
                timestamp=datetime.now().isoformat(),
            )
            if hasattr(self, "cli"):
                self.cli.log_graph(f"Added node: {target} (type={target_type})")
                self.cli.log_graph("Added node: virustotal (type=tool)")
                self.cli.log_graph(
                    f"Added edge: {target} → virustotal (label=vt_query)"
                )

            # Graph some relationships
            if hasattr(self, "graph"):
                self.graph.add_node(target, type=target_type)
                self.graph.add_node("virustotal", type="tool")

                self.graph.add_edge(
                    target,
                    "virustotal",
                    label="vt_query",
                    timestamp=datetime.now().isoformat(),
                )
                if hasattr(self, "cli"):
                    self.cli.log_graph(f"Added node: {target} (type={target_type})")
                    self.cli.log_graph("Added node: virustotal (type=tool)")
                    self.cli.log_graph(
                        f"Added edge: {target} → virustotal (label=vt_query)"
                    )

                # Tags
                for tag in attributes.get("tags", []):
                    self.graph.add_node(tag, type="vt_tag")
                    self.graph.add_edge(
                        "virustotal",
                        tag,
                        label="tag",
                        timestamp=datetime.now().isoformat(),
                    )
                    if hasattr(self, "cli"):
                        self.cli.log_graph(f"Added node: {tag} (type=vt_tag)")
                        self.cli.log_graph(
                            f"Added edge: virustotal → {tag} (label=tag)"
                        )

                # Categories
                for cat_val in attributes.get("categories", {}).values():
                    self.graph.add_node(cat_val, type="vt_category")
                    self.graph.add_edge(
                        "virustotal",
                        cat_val,
                        label="category",
                        timestamp=datetime.now().isoformat(),
                    )
                    if hasattr(self, "cli"):
                        self.cli.log_graph(f"Added node: {cat_val} (type=vt_category)")
                        self.cli.log_graph(
                            f"Added edge: virustotal → {cat_val} (label=category)"
                        )

                # Reputation
                rep = attributes.get("reputation")
                if rep is not None:
                    rep_node = f"vt_reputation:{rep}"
                    self.graph.add_node(rep_node, type="vt_score")
                    self.graph.add_edge(
                        "virustotal",
                        rep_node,
                        label="reputation",
                        timestamp=datetime.now().isoformat(),
                    )
                    if hasattr(self, "cli"):
                        self.cli.log_graph(f"Added node: {rep_node} (type=vt_score)")
                        self.cli.log_graph(
                            f"Added edge: virustotal → {rep_node} (label=reputation)"
                        )

                # Stats (e.g., malicious: 3)
                stats = attributes.get("last_analysis_stats", {})
                for key, val in stats.items():
                    if val > 0:
                        stat_node = f"vt_{key}:{val}"
                        self.graph.add_node(stat_node, type="vt_stat")
                        self.graph.add_edge(
                            "virustotal",
                            stat_node,
                            label="analysis",
                            timestamp=datetime.now().isoformat(),
                        )
                        if hasattr(self, "cli"):
                            self.cli.log_graph(
                                f"Added node: {stat_node} (type=vt_stat)"
                            )
                            self.cli.log_graph(
                                f"Added edge: virustotal → {stat_node} (label=analysis)"
                            )

    def classify_target(self, value):
        if value.startswith("http"):
            return "url"
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
            return "ip"
        else:
            return "domain"
