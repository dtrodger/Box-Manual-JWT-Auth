"""
Box Consulting - Box JWT Access Token Generation

To authenticate to the Box API the application needs to create a signed JWT assertion that can be exchanged
for a traditional OAuth 2.0 Access Token. A JWT assertion is essentially an encrypted JSON object, consisting
of a header, claims, and signature.
"""

import os
import json
import time
import logging.config
from urllib.request import urlopen
from urllib.request import Request
from urllib.parse import urlencode

import click
import jwt
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key


BOX_AUTH_SERVICE = "https://api.box.com/oauth2/token"
JWT_AUTH_FILE_RELATIVE_PATH = os.path.join(os.path.dirname(__name__), "jwt_auth.json")

# Set up a logger with the name of this module
log = logging.getLogger(__name__)


def configure_logging():
    """
    Configure INFO level logging to stdout
    """
    logging.basicConfig(level=logging.INFO)


def load_jwt_auth_json_to_dict():
    """
    Load JSON config at [path to project]/jwt_auth.json into a dictionary.
    """
    with open(JWT_AUTH_FILE_RELATIVE_PATH) as fh:
        jwt_auth_keys = json.load(fh)

    log.info(f"\n\nloaded Box JWT keys {jwt_auth_keys}\n\n")

    return jwt_auth_keys


def build_rsa_private_key(jwt_auth_keys):
    """
    To create the JWT assertion the application needs the private key from the configuration dictionary. This private
    key is encrypted and requires a passcode to unlock. Both the encrypted key and passcode are provided in the
    configuration dictionary.
    """
    encrypted_private_key = jwt_auth_keys["boxAppSettings"]["appAuth"]["privateKey"]
    private_key_passphrase = jwt_auth_keys["boxAppSettings"]["appAuth"]["passphrase"]
    rsa_private_key = load_pem_private_key(
        data=encrypted_private_key.encode("utf8"),
        password=private_key_passphrase.encode("utf8"),
        backend=default_backend(),
    )

    log.info(f"\n\ndecrypted private key into obj {rsa_private_key}\n\n")

    return rsa_private_key


def build_jwt_claims(jwt_auth_keys):
    """
    Build JWT claims dictionary from the loaded JWT keys.
    """
    claims = dict(
        iss=jwt_auth_keys["boxAppSettings"]["clientID"],
        sub=jwt_auth_keys["enterpriseID"],
        box_sub_type="enterprise",
        aud=BOX_AUTH_SERVICE,
        jti=secrets.token_hex(64),
        exp=round(time.time()) + 60,
    )

    log.info(f"\n\nbuilt JWT claims {claims}\n\n")

    return claims


def build_jwt_assertion(jwt_auth_keys, claims, rsa_private_key):
    """
    Build the JWT assertion from the loaded JWT keys, claims and decrypted private key. Assertions are formatted as
    HEADER.PAYLOAD.SIGNATURE

    Header = {'typ': 'JWT', 'alg': 'RS512'}
    Payload = Claims
    Signature = "{"typ": "JWT", "alg": "RS512"}.Claims" -> Signed with the RSA private key
    """
    key_id = jwt_auth_keys["boxAppSettings"]["appAuth"]["publicKeyID"]

    jwt_assertion = jwt.encode(
        claims, rsa_private_key, algorithm="RS512", headers=dict(kid=key_id)
    )

    log.info(f"\n\nbuilt JWT assertion {jwt_assertion}\n\n")

    return jwt_assertion


def call_box_auth_service_for_access_token(jwt_auth_keys, jwt_assertion):
    """
    Construct a HTTP request from the loaded JWT keys, and JWT assertion, then call Box's authentication service
    to get a temporary access token.
    """
    params = urlencode(
        dict(
            grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=jwt_assertion,
            client_id=jwt_auth_keys["boxAppSettings"]["clientID"],
            client_secret=jwt_auth_keys["boxAppSettings"]["clientSecret"],
        )
    ).encode()

    access_token = None
    try:
        request = Request(BOX_AUTH_SERVICE, params)
        response = urlopen(request).read()
        access_token = json.loads(response)["access_token"]

        log.info(
            f"\n\nGot access token from Box authentication service {access_token}\n\n"
        )
    except Exception as e:
        log.error(f"Failed HTTP callout to Box authentication service")

    return access_token


@click.command()
@click.option(
    "-c",
    "--call-auth",
    default=True,
    help="Application configuration file alias",
    type=str
)
def do_box_jwt_auth(call_auth):
    if not os.path.exists(JWT_AUTH_FILE_RELATIVE_PATH):
        jwt_auth_file_absolute_path = os.path.join(
            os.getcwd(), JWT_AUTH_FILE_RELATIVE_PATH
        )
        raise FileNotFoundError(
            f"Box JWT keys must be added to the file system path {jwt_auth_file_absolute_path} to continue"
        )

    configure_logging()
    jwt_auth_keys = load_jwt_auth_json_to_dict()
    claims = build_jwt_claims(jwt_auth_keys)
    rsa_private_key = build_rsa_private_key(jwt_auth_keys)
    jwt_assertion = build_jwt_assertion(jwt_auth_keys, claims, rsa_private_key)
    if call_auth:
        access_token = call_box_auth_service_for_access_token(jwt_auth_keys, jwt_assertion)


@click.group()
def cli() -> None:
    pass


def main():
    [
        cli.add_command(command)
        for command in [
            do_box_jwt_auth
        ]
    ]
    cli()


if __name__ == "__main__":
    main()
