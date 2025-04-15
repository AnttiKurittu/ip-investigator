import os
from pathlib import Path
from datetime import datetime


class History:
    help = (
        "history: List previous investigation targets and select one.\n"
        "Usage:\n"
        "  history                → show up to 50 recent targets\n"
        "  history <number>       → select that target from last list\n"
        "  history <filter-text>  → fuzzy search by domain or timestamp\n"
        "Note: URLs are excluded from this list.\n"
        "Supported target types: none"
    )

    targets = []  # ❗ allows running without a target set

    def __init__(self):
        self.sorted_history = []

    def run(self, target, args):
        if not hasattr(self, "cli"):
            print("\033[91mError:\033[0m History module must be bound to CLI instance.")
            return

        log_dir = Path("log")
        if not log_dir.exists():
            print("\033[91mNo log directory found.\033[0m")
            return

        target_map = {}
        for file in log_dir.glob("*.log"):
            parts = file.stem.split("_", 1)
            if len(parts) != 2:
                continue
            tgt, timestamp = parts
            if tgt.startswith("http") or "." not in tgt or len(tgt) > 100:
                continue
            try:
                dt = datetime.strptime(timestamp, "%Y-%m-%d-%H-%M-%S")
                if tgt not in target_map or dt > target_map[tgt]:
                    target_map[tgt] = dt
            except ValueError:
                continue

        full_history = sorted(target_map.items(), key=lambda x: x[1], reverse=True)

        # ─────────────────────────────────────────────────────
        # Case: selection by number
        if args and args[0].isdigit():
            if hasattr(self.cli, "history_last_results"):
                filtered = self.cli.history_last_results
            else:
                filtered = full_history[:50]
            index = int(args[0]) - 1
            if 0 <= index < len(filtered):
                new_target = filtered[index][0]
                print(f"\033[92mSwitching to target:\033[0m {new_target}")
                self.cli.onecmd(f"target {new_target}")
                self.cli.log(f"[history] Target changed to {new_target} via history.")
            else:
                print(f"\033[91mError:\033[0m Selection {args[0]} out of range.")
            return

        # ─────────────────────────────────────────────────────
        # Case: fuzzy search term
        if args:
            search = " ".join(args).lower()
            filtered = [
                (tgt, dt)
                for tgt, dt in full_history
                if search in tgt.lower() or search in dt.strftime("%Y-%m-%d %H:%M:%S")
            ]
            if not filtered:
                print(f"\033[91mNo matches found for:\033[0m '{search}'")
                return
            self.cli.history_last_results = filtered
        else:
            filtered = full_history[:50]
            self.cli.history_last_results = filtered

        # ─────────────────────────────────────────────────────
        print("\033[94mMatching targets:\033[0m")
        for idx, (tgt, dt) in enumerate(filtered, 1):
            print(f"[{idx}] {dt.strftime('%Y-%m-%d %H:%M:%S')} - {tgt}")
