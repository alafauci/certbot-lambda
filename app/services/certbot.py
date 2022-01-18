from pathlib import Path
from dataclasses import dataclass
import certbot.main


@dataclass
class CertFile:
    name: str
    content: str


@dataclass
class Cert:
    domain: str
    files: list[CertFile]


def obtain_certbot_certs(
    emails: list[str],
    domains: list[str],
    dns_plugin: str,
    certbot_dir: Path,
    certbot_server: str,
) -> list[Cert]:
    certbot_args = [
        # Override directory paths so script doesn't have to be run as root
        "--config-dir",
        str(certbot_dir),
        "--work-dir",
        str(certbot_dir),
        "--logs-dir",
        str(certbot_dir),
        # Obtain a cert but don't install it
        "certonly",
        # Run in non-interactive mode
        "--non-interactive",
        # Agree to the terms of service
        "--agree-tos",
        # Email of domain administrators
        "--email",
        ",".join(emails),
        # Use dns challenge with dns plugin
        "--authenticator",
        dns_plugin,
        "--preferred-challenges",
        "dns-01",
        # Use this server instead of default acme-v01
        "--server",
        certbot_server,
        # Domains to provision certs for (comma separated)
        "--domains",
        ",".join(domains),
    ]
    certbot.main.main(certbot_args)

    return read_certs_from_path(certbot_dir.joinpath("live"), domains)


def read_certs_from_path(path: Path, domains: list[str]) -> list[Cert]:
    certs: list[Cert] = []
    cert_files = ["fullchain.pem", "chain.pem", "privkey.pem", "cert.pem"]

    for domain in domains:
        domain_path = path.joinpath(domain)

        if not domain_path.is_dir():
            raise RuntimeError(
                f"Failed to generate cert for {domain}: {domain_path} is not a directory"
            )

        cert = Cert(domain=domain, files=[])

        for cert_file in cert_files:
            cert_path = domain_path.joinpath(cert_file)

            if not cert_path.is_file():
                raise RuntimeError(
                    f"Failed to generate cert for {domain}: {cert_path} not found"
                )

            content = cert_path.read_text()

            if len(content) < 50:
                raise RuntimeError(
                    f"Failed to generate cert for {domain}: {cert_path} cert is incorrect"
                )

            cert.files.append(CertFile(name=cert_path.name, content=content))

        certs.append(cert)

    return certs
