import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import hashlib


class Cert:
    help = (
        "cert: Retrieve and display the SSL/TLS certificate for a domain or URL.\n"
        "Usage: cert\n"
        "Supported target types: domain, url"
    )

    targets = ["domain", "url"]

    def run(self, target, args):
        original_target = target

        if target.startswith("http://"):
            print("\033[91mError:\033[0m HTTP does not use certificates.")
            return

        if not target.startswith("https://"):
            print(
                f"\033[93mNote:\033[0m Using 'https://{target}' to fetch the certificate."
            )
            target = f"https://{target}"

        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443

        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_bin = ssock.getpeercert(binary_form=True)
        except Exception as e:
            print(f"\033[91mError:\033[0m Failed to retrieve certificate: {e}")
            return

        print(f"\033[94mCertificate for {host}:{port}\033[0m")

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        print("\033[92mSubject Details:\033[0m")
        for key in (
            "commonName",
            "organizationName",
            "organizationalUnitName",
            "localityName",
            "stateOrProvinceName",
            "countryName",
        ):
            self.print_field(key, subject.get(key))

        print("\n\033[92mIssuer Details:\033[0m")
        for key in ("commonName", "organizationName", "countryName"):
            self.print_field(key, issuer.get(key))

        self.print_field("Serial Number", cert.get("serialNumber"))
        self.print_field("Version", cert.get("version"))
        self.print_field("Not Before", cert.get("notBefore"))
        self.print_field("Not After", cert.get("notAfter"))

        alt_names = cert.get("subjectAltName")
        if alt_names:
            print("\n\033[93mSubject Alt Names:\033[0m")
            for typ, name in alt_names:
                print(f"  - {typ}: {name}")

        sha1 = hashlib.sha1(cert_bin).hexdigest().upper()
        sha256 = hashlib.sha256(cert_bin).hexdigest().upper()
        self.print_field(
            "SHA-1 Fingerprint",
            ":".join(sha1[i : i + 2] for i in range(0, len(sha1), 2)),
        )
        self.print_field(
            "SHA-256 Fingerprint",
            ":".join(sha256[i : i + 2] for i in range(0, len(sha256), 2)),
        )

        # ─── Graph Integration ────────────────────────────────
        if hasattr(self, "graph") and hasattr(self, "cli"):
            self.graph.add_node(host, type="domain")
            self.cli.log_graph(f"Added node: {host} (type=domain)")

            subject_cn = subject.get("commonName", "Unknown CN")
            self.graph.add_node(subject_cn, type="cert_subject")
            self.cli.log_graph(f"Added node: {subject_cn} (type=cert_subject)")

            self.graph.add_edge(
                host,
                subject_cn,
                label="cert_subject",
                timestamp=datetime.now().isoformat(),
            )
            self.cli.log_graph(
                f"Added edge: {host} → {subject_cn} (label=cert_subject)"
            )

            # Subject metadata
            for key, label, ntype in [
                ("organizationName", "Org", "org"),
                ("countryName", "Country", "country"),
                ("stateOrProvinceName", "Region", "region"),
            ]:
                val = subject.get(key)
                if val:
                    self.graph.add_node(val, type=ntype)
                    self.cli.log_graph(f"Added node: {val} (type={ntype})")
                    self.graph.add_edge(
                        subject_cn,
                        val,
                        label=label,
                        timestamp=datetime.now().isoformat(),
                    )
                    self.cli.log_graph(
                        f"Added edge: {subject_cn} → {val} (label={label})"
                    )

            # Issuer organization
            issuer_org = issuer.get("organizationName")
            if issuer_org:
                self.graph.add_node(issuer_org, type="issuer_org")
                self.cli.log_graph(f"Added node: {issuer_org} (type=issuer_org)")
                self.graph.add_edge(
                    subject_cn,
                    issuer_org,
                    label="issued_by",
                    timestamp=datetime.now().isoformat(),
                )
                self.cli.log_graph(
                    f"Added edge: {subject_cn} → {issuer_org} (label=issued_by)"
                )

            # SAN entries
            if alt_names:
                for typ, name in alt_names:
                    if typ == "DNS":
                        self.graph.add_node(name, type="san")
                        self.cli.log_graph(f"Added node: {name} (type=san)")
                        self.graph.add_edge(
                            subject_cn,
                            name,
                            label="SAN",
                            timestamp=datetime.now().isoformat(),
                        )
                        self.cli.log_graph(
                            f"Added edge: {subject_cn} → {name} (label=SAN)"
                        )

    def print_field(self, label, value):
        if value:
            print(f"\033[93m{label}:\033[0m {value}")
