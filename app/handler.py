#!/usr/bin/env python3

import shutil
from certbot._internal.plugins import disco as plugins_disco
from os import environ

from app.settings import load_settings
from app.services.certbot import obtain_certbot_certs
from app.services.aws import upload_certs_as_secrets
import boto3
from OpenSSL import crypto
from slugify import slugify
import datetime
import json

def is_cert_valid(domain):
    secret_name = f"certbot-{slugify(domain)}"
    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret = json.loads(get_secret_value_response['SecretString'])
        certificate = secret['cert.pem']
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

        expiry_date = x509.get_notAfter().decode('utf-8')
        expiry_date = datetime.datetime.strptime(expiry_date, '%Y%m%d%H%M%SZ')
        return expiry_date - datetime.datetime.utcnow() > datetime.timedelta(days=30)
    except Exception as e:
        print(f"Error checking certificate validity for {domain}: {e}")
        # Assume renewal is needed if there's an error
        return False


# def handler(_event, _context):
#     if environ.get("TESTMODE") == "true":
#         plugins = list(plugins_disco.PluginsRegistry.find_all())
#         dns_plugins = [v for v in plugins if v.startswith("dns-")]
#
#         if len(dns_plugins) != 14:
#             raise Exception("Failed to discover all certbot DNS plugins")
#
#         return
#     else:
#         settings = load_settings()
#
#         try:
#             shutil.rmtree(str(settings.CERTBOT_DIR), ignore_errors=True)
#
#             certs = obtain_certbot_certs(
#                 emails=settings.CERTBOT_EMAILS,
#                 domains=settings.CERTBOT_DOMAINS,
#                 dns_plugin=settings.CERTBOT_DNS_PLUGIN,
#                 certbot_dir=settings.CERTBOT_DIR,
#                 certbot_server=settings.CERTBOT_SERVER,
#                 preferred_chain=settings.CERTBOT_PREFERRED_CHAIN,
#                 extra_args=settings.CERTBOT_EXTRA_ARGS,
#                 credentials=settings.CERTBOT_CREDENTIALS,
#                 propagation_seconds=settings.CERTBOT_PROPAGATION_SECONDS,
#             )
#
#             upload_certs_as_secrets(
#                 certs,
#                 name=settings.AWS_SECRET_NAME,
#                 description=settings.AWS_SECRET_DESCRIPTION,
#             )
#         finally:
#             shutil.rmtree(str(settings.CERTBOT_DIR), ignore_errors=True)
#
#     return "Certificates obtained and uploaded successfully."

def handler(_event, _context):
    if environ.get("TESTMODE") == "true":
        plugins = list(plugins_disco.PluginsRegistry.find_all())
        dns_plugins = [v for v in plugins if v.startswith("dns-")]

        if len(dns_plugins) != 14:
            raise Exception("Failed to discover all certbot DNS plugins")

        return
    else:
        settings = load_settings()

        try:
            shutil.rmtree(str(settings.CERTBOT_DIR), ignore_errors=True)

            for domain in settings.CERTBOT_DOMAINS:
                if not is_cert_valid(domain):
                    certs = obtain_certbot_certs(
                        emails=settings.CERTBOT_EMAILS,
                        domains=[domain],  # Renew only the necessary domain
                        dns_plugin=settings.CERTBOT_DNS_PLUGIN,
                        certbot_dir=settings.CERTBOT_DIR,
                        certbot_server=settings.CERTBOT_SERVER,
                        preferred_chain=settings.CERTBOT_PREFERRED_CHAIN,
                        extra_args=settings.CERTBOT_EXTRA_ARGS,
                        credentials=settings.CERTBOT_CREDENTIALS,
                        propagation_seconds=settings.CERTBOT_PROPAGATION_SECONDS,
                    )

                    upload_certs_as_secrets(
                        certs,
                        name=settings.AWS_SECRET_NAME.format(domain=slugify(domain)),
                        description=settings.AWS_SECRET_DESCRIPTION,
                    )
                else:
                    print(f"Certificate for {domain} is still valid for more than 30 days. Skipping renewal.")

        finally:
            shutil.rmtree(str(settings.CERTBOT_DIR), ignore_errors=True)

    return "Certificate renewal process completed."

if __name__ == "__main__":
    handler(None, None)
