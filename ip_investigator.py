import cmd
import os
import sys
import importlib.util
import argparse
import datetime
import re
import configparser
from pathlib import Path
from urllib.parse import urlparse
from io import StringIO
from contextlib import redirect_stdout
import readline
import atexit
import networkx as nx

HISTORY_FILE = Path(__file__).parent / ".cli_history"

# Load previous session history if available
if HISTORY_FILE.exists():
    readline.read_history_file(HISTORY_FILE)

# Save session history on exit
atexit.register(readline.write_history_file, HISTORY_FILE)

LOG_DIR = Path(__file__).parent / "log"
SAVE_DIR = Path(__file__).parent / "saves"
MODULES_DIR = Path(__file__).parent / "modules"


def strip_ansi(text):
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


class IPInvestigatorCLI(cmd.Cmd):
    intro = "Welcome to the IP Investigator. Type help or ? to list commands.\n"
    prompt = "[target: none] > "

    def __init__(self):
        super().__init__()
        self.graph = nx.DiGraph()
        self.modules = self.load_modules()
        self.target = None
        self.target_type = None
        self.log_file = None
        self.session_log_file = None
        self.session_log_path = None
        self.init_session_log()
        LOG_DIR.mkdir(exist_ok=True)
        SAVE_DIR.mkdir(exist_ok=True)

    def init_session_log(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        self.session_log_path = LOG_DIR / f"session_{timestamp}.log"
        self.session_log_file = open(self.session_log_path, "a")

    def load_modules(self):
        modules = {}
        for file in os.listdir(MODULES_DIR):
            if file.endswith(".py") and not file.startswith("__"):
                module_name = file[:-3]
                file_path = MODULES_DIR / file
                try:
                    spec = importlib.util.spec_from_file_location(
                        module_name, file_path
                    )
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    cls = getattr(mod, module_name.capitalize(), None)
                    if cls:
                        instance = cls()
                        instance.cli = self  # 👈 Binds main CLI instance to the module
                        instance.graph = self.graph  # 👈 expose graph to modules
                        modules[module_name] = instance
                except Exception as e:
                    print(f"Failed to load module '{module_name}': {e}")
        return modules

    def do_target(self, arg):
        if not arg:
            print("Usage: target <IP|domain|url>")
            return
        self.target = arg
        self.target_type = self.classify_target(arg)
        self.prompt = f"[\033[93mtarget\033[0m (\033[96m{self.target_type}\033[0m): \033[97m{self.target}\033[0m] > "

        self.init_log_file()
        self.log(f"[target] Target set to {self.target} ({self.target_type})")

    def classify_target(self, target):
        if re.match(r"^https?://", target):
            return "url"
        elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return "ip"
        else:
            return "domain"

    def init_log_file(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")

        # Sanitize target for safe filename (no slashes or special chars)
        safe_target = re.sub(r"[^\w.-]", "_", self.target)

        self.log_file_path = LOG_DIR / f"{safe_target}_{timestamp}.log"
        self.log_file = open(self.log_file_path, "a")

    def log(self, text, module_name=None):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = text.strip().splitlines()
        for line in lines:
            clean_line = strip_ansi(line)
            prefix = f"[{timestamp}]"
            if module_name:
                prefix += f" [{module_name}]"
            formatted_line = f"{prefix} {clean_line}"
            if self.log_file:
                self.log_file.write(formatted_line + "\n")
            if self.session_log_file:
                self.session_log_file.write(formatted_line + "\n")
        if self.log_file:
            self.log_file.flush()
        if self.session_log_file:
            self.session_log_file.flush()

    def do_exportgraph(self, arg):
        if not hasattr(self, "graph") or not self.graph:
            print("No graph to export.")
            return

        filename = arg.strip() if arg.strip() else "session_graph.dot"
        dot_path = Path(filename)

        with open(dot_path, "w") as f:
            f.write("digraph G {\n")
            f.write("  rankdir=LR;\n")  # Left to right layout
            f.write('  node [style=filled, fontname="Helvetica"];\n')

            for node, attrs in self.graph.nodes(data=True):
                label = node
                ntype = attrs.get("type", "default")
                shape = "ellipse"
                color = "white"

                if ntype == "ip":
                    shape = "box"
                    color = "lightblue"
                elif ntype == "domain":
                    shape = "ellipse"
                    color = "lightgreen"
                elif ntype == "hostname":
                    shape = "oval"
                    color = "gold"
                elif ntype == "cert_subject":
                    shape = "hexagon"
                    color = "cyan"
                elif ntype in ["org", "issuer_org"]:
                    shape = "diamond"
                    color = "lightcoral"
                elif ntype == "port":
                    shape = "circle"
                    color = "orange"
                elif ntype == "san":
                    shape = "note"
                    color = "lightgray"

                f.write(
                    f'  "{node}" [label="{label}", shape={shape}, fillcolor="{color}"];\n'
                )

            for src, dst, attrs in self.graph.edges(data=True):
                label = attrs.get("label", "")
                timestamp = attrs.get("timestamp", "")
                edge_label = f"{label} ({timestamp})" if timestamp else label
                f.write(f'  "{src}" -> "{dst}" [label="{edge_label}"];\n')

            f.write("}\n")

        print(f"Graph exported to {dot_path}")

    def default(self, line):
        parts = line.strip().split()
        if not parts:
            return

        cmd_name = parts[0]
        args = parts[1:]

        module = self.modules.get(cmd_name)
        if not module:
            print(f"Unknown command: {cmd_name}")
            return

        # Check if the module requires a target
        if module.targets:
            if not self.target:
                print("Please set a target first using the 'target' command.")
                return

            if self.target_type not in module.targets:
                if self.target_type == "url" and "domain" in module.targets:
                    parsed = urlparse(self.target)
                    if parsed.hostname:
                        print(
                            f"\033[93mNote:\033[0m Extracted domain '{parsed.hostname}' from URL."
                        )
                        target = parsed.hostname
                    else:
                        print("Could not extract domain from URL.")
                        return
                else:
                    print(
                        f"This module does not support targets of type '{self.target_type}'."
                    )
                    return
            else:
                target = self.target
        else:
            # Modules like history that don't require a target
            target = self.target  # May still be None

        # Run the module and capture its output
        buffer = StringIO()
        with redirect_stdout(buffer):
            try:
                module.run(target, args)
            except Exception as e:
                print(f"Error running {cmd_name}: {e}")

        output = buffer.getvalue()
        print(output, end="")
        self.log(f"[{cmd_name}] {output}")

    def do_help(self, arg):
        if not arg:
            print("Available commands:")
            print("  target <IP|domain|url>")
            print("  reload")
            print("  log")
            print("  save")
            print("  load [filename]")
            print("  saveas <filename>")
            print("  clearlog")
            print("  listsaves")
            print("  exportgraph [filename]     (export session graph as .dot)")
            print("  help <module>")
            print("\nAvailable modules:")
            for name, mod in self.modules.items():
                target_info = (
                    ", ".join(mod.targets) if hasattr(mod, "targets") else "unknown"
                )
                print(f"  {name:<12} [{target_info}]")
        else:
            mod = self.modules.get(arg)
            if mod and hasattr(mod, "help"):
                print(mod.help)
            else:
                print(f"No help available for '{arg}'")

    def do_reload(self, _):
        self.modules = self.load_modules()
        print("Modules reloaded.")

    def do_log(self, _):
        if self.log_file:
            self.log_file.flush()
            with open(self.log_file_path) as f:
                print(f.read())
        else:
            print("No log file is currently active.")

    def log_graph(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] [graph] {message}"
        if self.session_log_file:
            self.session_log_file.write(strip_ansi(line) + "\n")
            self.session_log_file.flush()

    def do_clearlog(self, _):
        if self.session_log_file:
            self.session_log_file.close()
            open(self.session_log_path, "w").close()
            self.session_log_file = open(self.session_log_path, "a")
            print("Session log cleared.")
        else:
            print("No session log file to clear.")

    def do_saveas(self, filename):
        if not self.log_file:
            print("No log file to save.")
            return
        dest_path = LOG_DIR / filename
        with open(dest_path, "w") as dest, open(self.log_file_path) as src:
            dest.write(src.read())
        print(f"Log saved as {filename}.")

    def do_save(self, _):
        if not self.target or not self.log_file:
            print("No active investigation to save.")
            return
        save_file = SAVE_DIR / f"{self.target}.save"
        config = configparser.ConfigParser()
        config["session"] = {
            "target": self.target,
            "target_type": self.target_type,
            "log_path": str(self.log_file_path),
        }
        with open(save_file, "w") as f:
            config.write(f)
        self.log("[save] Investigation session saved.")
        print(f"Session saved to {save_file.name}.")

    def do_load(self, filename=None):
        if not filename:
            saves = sorted(SAVE_DIR.glob("*.save"), key=os.path.getmtime, reverse=True)
            if not saves:
                print("No save files found.")
                return
            save_file = saves[0]
            print(f"Loading latest save: {save_file.name}")
        else:
            save_file = SAVE_DIR / filename
            if not save_file.exists():
                print(f"Save file {filename} does not exist.")
                return

        config = configparser.ConfigParser()
        config.read(save_file)
        try:
            self.target = config["session"]["target"]
            self.target_type = config["session"]["target_type"]
            self.log_file_path = Path(config["session"]["log_path"])
            self.log_file = open(self.log_file_path, "a")
            self.prompt = f"[\033[93mtarget\033[0m (\033[96m{self.target_type}\033[0m): \033[97m{self.target}\033[0m] > "

            self.log("[load] Investigation session loaded.")
            print(f"Session loaded for target: {self.target}")
        except KeyError as e:
            print(f"Missing key in save file: {e}")

    def do_listsaves(self, _):
        saves = sorted(SAVE_DIR.glob("*.save"), key=os.path.getmtime, reverse=True)
        if not saves:
            print("No saved sessions found.")
            return
        print("Available saved sessions:")
        for save in saves:
            timestamp = datetime.datetime.fromtimestamp(save.stat().st_mtime)
            print(
                f"  {save.name} (last modified: {timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
            )

    def do_exit(self, _):
        print("Exiting.")
        if self.log_file:
            self.log_file.close()
        if self.session_log_file:
            self.session_log_file.close()
        return True

    def do_EOF(self, _):
        return self.do_exit(_)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Set initial target")
    parser.add_argument(
        "-c",
        "--command",
        nargs="*",
        help="Run one or more commands after setting target",
    )
    parser.add_argument(
        "--exit-after", action="store_true", help="Exit after running commands"
    )
    parser.add_argument("--saveas", help="Save log with given filename after commands")
    args = parser.parse_args()

    cli = IPInvestigatorCLI()

    if args.target:
        cli.do_target(args.target)

    if args.command:
        for cmd_name in args.command:
            cli.default(cmd_name)

    if args.saveas:
        cli.do_saveas(args.saveas)

    if args.exit_after:
        cli.do_exit(None)
    else:
        cli.cmdloop()


if __name__ == "__main__":
    main()
