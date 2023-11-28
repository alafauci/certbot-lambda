from boto3 import client
import json
from slugify import slugify
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import base64

from .certbot import Cert


# def upload_certs_as_secrets(
#     certs: list[Cert], name: str, description: str = ""
# ) -> None:
#     for cert in certs:
#         name = name.format(domain=slugify(cert.domain))
#
#         create_or_update_secret(
#             name=name,
#             data={f.name: f.content for f in cert.files},
#             description=description,
#         )
def upload_certs_as_secrets(
    certs: list[Cert], name: str, description: str = ""
) -> None:
    for cert in certs:
        formatted_name = name.format(domain=slugify(cert.domain))

        # Assuming cert.certificate and cert.private_key are in PEM format
        cert_obj = x509.load_pem_x509_certificate(cert.certificate.encode())
        private_key_obj = serialization.load_pem_private_key(cert.private_key.encode(), password=None)

        # Assuming cert.chain is optional and in PEM format if present
        chain = None
        if hasattr(cert, 'chain') and cert.chain:
            chain = [x509.load_pem_x509_certificate(cert.chain.encode())]

        p12 = pkcs12.serialize_key_and_certificates(
            name=formatted_name.encode(),
            key=private_key_obj,
            cert=cert_obj,
            cas=chain,
            encryption_algorithm=serialization.NoEncryption()
        )

        encoded_p12 = base64.b64encode(p12).decode('utf-8')

        # Combine the original data with the p12 file
        data = {f.name: f.content for f in cert.files}
        data['p12'] = encoded_p12

        create_or_update_secret(
            name=formatted_name,
            data=data,
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
