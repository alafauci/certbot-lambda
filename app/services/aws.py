from boto3 import client
import json
from slugify import slugify
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import base64

from .certbot import Cert


def is_cert_valid(secret_name):
    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        certificate = get_secret_value_response['SecretString']
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

        expiry_date = x509.get_notAfter().decode('utf-8')
        expiry_date = datetime.datetime.strptime(expiry_date, '%Y%m%d%H%M%SZ')
        return expiry_date - datetime.datetime.utcnow() > datetime.timedelta(days=30)
    except Exception as e:
        print(f"Error checking certificate validity: {e}")
        # If there's an error (e.g., certificate not found), we assume renewal is needed
        return False


def upload_certs_as_secrets(
    certs: list[Cert], name: str, description: str = ""
) -> None:
    for cert in certs:
        name = name.format(domain=slugify(cert.domain))

        create_or_update_secret(
            name=name,
            data={f.name: f.content for f in cert.files},
            description=description,
        )


def create_or_update_secret(
    name: str,
    data: dict[str, str],
    description: str = "",
):
    secretsmanager = client("secretsmanager")

    try:
        secretsmanager.create_secret(
            Name=name,
            Description=description,
            SecretString=json.dumps(data),
        )
        print(f"Creating a new secret {name}")
    except secretsmanager.exceptions.ResourceExistsException:
        print(f"Updating secret {name} with new certs")

        secretsmanager.put_secret_value(SecretId=name, SecretString=json.dumps(data))
