# IP Investigator 🕵️‍♂️

**IP Investigator** is a modular command-line tool for investigating IP addresses, domains, and URLs. It supports live lookups using popular APIs and built-in tools, logging all results, and building graph-based visualizations of the relationships uncovered during an investigation. This is a project I put together in a day testing ChatGPT as a coding assistant - feel like this should be mentioned.

It also wrote the README which explains the emojis.

---

## 🚀 Features

- 🔍 Interactive CLI with modular plugin support
- 🎯 Targets: IP, Domain, and URL
- 📦 Modules:
  - `ping` – Ping target to check reachability
  - `whois` – Perform WHOIS lookups
  - `dnslookup` – DNS records & reverse DNS
  - `cert` – Retrieve SSL certificates
  - `ipinfo` – Enrich with IPInfo.io data
  - `stinfo` – Enrich with SecurityTrails DNS data
  - `pdns` – Passive DNS history from Mnemonic
  - `shodan` – IoT and port scanning intelligence
  - `nmap` – Quick Nmap port scan and service detection
  - `webrequest` – Interrogate web services on common ports
  - `vt` – VirusTotal enrichment (IP, domain, URL)
  - `retarget` – Extract IPs/domains/URLs from current log and reassign target
  - `history` – View and reuse previously investigated targets
- 🧠 Session-wide graph building (`exportgraph`) with DOT export
- 🗂 Persistent logs (per-target and per-session)
- 🧠 Smart CLI with fuzzy matching and Bash-style command history

---

## 📦 Installation

### 1. Clone this repo:

```bash
git clone https://github.com/AnttiKurittu/ip-investigator
cd ip-investigator
```

### 2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install requirements:

```bash
pip install -r requirements.txt
```

---

## 🔐 API Keys

Some modules require API keys. Create the following `.conf` files in the `modules/` directory:

### `ipinfo.conf` (not required but increased quota)

```ini
[DEFAULT]
api_key = your_ipinfo_token_here
```

### `stinfo.conf` (required)

```ini
[DEFAULT]
api_key = your_securitytrails_key_here
```

### `vt.conf` (required)

```ini
[DEFAULT]
api_key = your_virustotal_api_key_here
```

### `shodan.conf` (required)

```ini
[DEFAULT]
api_key = your_shodan_key_here
```

---

## 🕹 Usage

### Start the tool:

```bash
python ip_investigator.py
```

### Command-Line Options

```bash
python ip_investigator.py -t <target> -c <module1> <module2> --exit-after
```

Example:

```bash
python ip_investigator.py -t 8.8.8.8 -c ping whois ipinfo --exit-after
```

---

## 📖 Commands (in CLI)

| Command          | Description                                |
|------------------|--------------------------------------------|
| `target <value>` | Set target (IP, domain, or URL)            |
| `ping`           | Ping the target                            |
| `whois`          | WHOIS lookup                               |
| `dnslookup`      | DNS records / reverse DNS                  |
| `cert`           | SSL certificate details                    |
| `ipinfo`         | IP info (IPInfo.io)                        |
| `stinfo`         | DNS & Infra data (SecurityTrails)          |
| `pdns`           | Passive DNS (Mnemonic)                     |
| `shodan`         | Shodan host lookup                         |
| `nmap`           | Quick TCP port scan                        |
| `webrequest`     | Check for HTTP/S endpoints and headers     |
| `vt`             | VirusTotal query (IP, domain, or URL)      |
| `retarget`       | Reassign target from extracted log entries |
| `history`        | Reuse previous targets                     |
| `save`           | Save current investigation session         |
| `load`           | Load saved session (defaults to last save) |
| `listsaves`      | List saved sessions                        |
| `log`            | Show current session log                   |
| `clearlog`       | Clear session log                          |
| `reload`         | Reload all modules                         |
| `exportgraph`    | Export DOT file of graph                   |
| `help`           | Show available modules and commands        |
| `exit`           | Exit and save session log. Abort to discard log (Ctrl-C) |

---

## 📊 Graph Output

- Each module contributes nodes and edges to a background graph
- Run `exportgraph investigation.dot` to save it as `investigation.dot`
- You can render the graph with tools like Graphviz (install separately):

```bash
dot -Tpng investigation.dot -o graph.png
```

---

## 🧩 Extending It

- All modules live in the `modules/` directory
- Each module is a Python class with:
  - `targets = ["ip", "domain", "url"]`
  - `help = "..."` string
  - `run(self, target, args)` method
- On startup or `reload`, all `.py` files are automatically loaded
- Add new modules without touching the main CLI

---

## 📝 License

See LICENSE

---

## 🙌 Acknowledgements

Thanks to:
- ChatGPT for assisting with development
- IPInfo.io, SecurityTrails, Shodan, VirusTotal, Mnemonic
- Graphviz & NetworkX
