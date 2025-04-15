import re


class Retarget:
    help = (
        "retarget: Extract IPs, domains, and URLs from the current log and select one as the new target.\n"
        "Usage:\n"
        "  retarget               → List all extracted targets from the log\n"
        "  retarget <search term> → Fuzzy search targets in log\n"
        "  retarget <number>      → Set the selected entry as the new target\n"
        "Supported target types: (operates independently of current type)"
    )

    targets = ["ip", "domain", "url"]

    def __init__(self):
        self.extracted = []
        self.filtered = []

    def run(self, target, args):
        if not hasattr(self, "cli"):
            print(
                "\033[91mError:\033[0m Retarget module must be bound to CLI instance."
            )
            return

        if not self.cli.log_file_path or not self.cli.log_file_path.exists():
            print("\033[91mError:\033[0m No active log file.")
            return

        if not self.extracted:
            self.extract_targets()

        # Handle number selection
        if args and args[0].isdigit():
            idx = int(args[0]) - 1
            source = self.filtered if self.filtered else self.extracted
            if 0 <= idx < len(source):
                new_target = source[idx]
                print(f"\033[92mRetargeting to:\033[0m {new_target}")
                self.cli.onecmd(f"target {new_target}")
                self.cli.log(f"[retarget] Target changed to {new_target} from log.")
            else:
                print(f"\033[91mError:\033[0m Selection {args[0]} is out of range.")
            return

        # Fuzzy search
        if args:
            query = " ".join(args).lower()
            self.filtered = [item for item in self.extracted if query in item.lower()]
            if not self.filtered:
                print("\033[91mNo matches found.\033[0m")
                return
            print(f"\033[94mFiltered matches for '{query}':\033[0m")
            for idx, item in enumerate(self.filtered, 1):
                print(f"[{idx}] {item}")
            return

        # Default listing
        self.filtered = []
        if not self.extracted:
            print("No IPs, domains, or URLs found in log.")
            return

        print("\033[94mAvailable targets from log:\033[0m")
        for idx, item in enumerate(self.extracted, 1):
            print(f"[{idx}] {item}")

    def extract_targets(self):
        with open(self.cli.log_file_path, "r") as f:
            lines = f.readlines()

        # Strip leading timestamps from each line (e.g., "[2025-04-15 17:57:26] ")
        stripped_lines = [
            re.sub(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*", "", line)
            for line in lines
        ]
        text = "".join(stripped_lines)

        # Extract IPv4
        ipv4s = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)

        # Extract IPv6
        ipv6s = re.findall(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b", text)

        # Domains
        domains = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)

        # URLs
        urls = re.findall(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\'"<>),\s]*', text)
        urls = [url.rstrip("'\").,<>") for url in urls]

        # Remove known false positives
        domains = [
            d for d in domains if not re.search(r"\.(log|txt|json)$", d, re.IGNORECASE)
        ]

        combined = set(ipv4s + ipv6s + domains + urls)
        self.extracted = sorted(combined)
