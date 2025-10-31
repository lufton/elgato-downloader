import argparse
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import string
import sys
import zipfile
from urllib.parse import urlparse

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv(".env")

DEFAULT_USERNAME = os.getenv("ELGATO_USERNAME")
DEFAULT_PASSWORD = os.getenv("ELGATO_PASSWORD")
CLIENT_ID = "streamdeck-v2"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
REDIRECT_URL = "https://oauth2-redirect.elgato.com/streamdeck/marketplace/auth/"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger.addHandler(handler)


def get_random_code_verifier() -> str:
    charset = string.ascii_letters + string.digits + "-._~"

    return ''.join(secrets.choice(charset) for _ in range(64))


def get_code_challenge(code_verifier: str) -> str:
    hashed = hashlib.sha256(code_verifier.encode('ascii')).digest()

    return base64.urlsafe_b64encode(hashed).decode('ascii').rstrip('=')


def get_access_token(username: str, password: str) -> str | None:
    logger.info("Getting access token...")

    code_verifier = get_random_code_verifier()
    code_challenge = get_code_challenge(code_verifier)

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = USER_AGENT
    response = session.get(
        f"https://account.elgato.com/auth/realms/mp/protocol/openid-connect/auth?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URL}&"
        f"scope=openid+offline_access&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )
    match = re.search(r'"loginAction":\s*"(.*?)"', response.text)

    if not match:
        return logger.error("Can't get sign in parameters from the page")

    response = session.post(
        url=match.group(1),
        data={
            "username": username,
            "password": password,
        },
        allow_redirects=False,
    )
    location = response.headers.get("Location")

    if not location:
        return logger.error("Make sure you have entered valid credentials")

    match = re.search(r"code=(.*?)(&|$)", location)

    if not match:
        return logger.error("Can't get sign in parameters from the page")

    response = session.post(
        url="https://account.elgato.com/auth/realms/mp/protocol/openid-connect/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": "secret",
            "code": match.group(1),
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URL,
        }
    )
    data = response.json()
    access_token = data["access_token"]

    logger.info(f"Access token is: {access_token}")

    return access_token


def get_extension(url, variant_name: str) -> tuple[str, str] | None:
    logger.info("Getting extension information...")

    response = requests.get(
        url=url,
        verify=False,
    )
    match = re.search(r'<script\s+id="__NEXT_DATA__".*?>(.*?)</script>', response.text, re.DOTALL)

    if not match:
        return logger.error("Can't get extension information")

    try:
        data = json.loads(match.group(1))
        extension = data["props"]["pageProps"]["content"]["extension"]
        variants = data["props"]["pageProps"]["content"]["variants"]
        default_variant = next((variant for variant in variants if variant["is_default"]))
        variant = (
            next((variant for variant in variants if variant["name"] == variant_name), None)
            if variant_name
            else default_variant
        )

        if not variant:
            logger.warning(f"Can't find {variant_name} variant, switching to default one")
            variant = default_variant

        logger.info(f"Extension is: {extension}, variant is: {variant['id']} ({variant['name']})")

        return extension, variant["id"]
    except Exception as e:
        logger.error(f"Can't parse extension page")


def get_session(access_token: str) -> requests.Session:
    logger.info("Getting session...")

    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = USER_AGENT
    session.headers["Authorization"] = f"Bearer {access_token}"

    return session


def get_my_products(session: requests.Session) -> list[str]:
    logger.info("Getting my products...")

    response = session.get("https://mp-gateway.elgato.com/my-products/succeeded-or-pending")
    data = response.json()
    my_products = data["succeeded"] + data["pending"]

    logger.info(f"My products are: {my_products}")

    return my_products


def is_purchased(session: requests.Session, variant_id: str) -> bool:
    logger.info(f"Checking if {variant_id} is purchased...")

    my_products = get_my_products(session)
    purchased = variant_id in my_products

    logger.info(f"{variant_id} is {'' if purchased else 'not '}purchased")

    return purchased


def purchase(session: requests.Session, variant_id: str) -> bool:
    logger.info(f"Purchasing {variant_id}...")

    response = session.post(
        url="https://mp-gateway.elgato.com/orders",
        json={"items": [{"origin": "marketplace", "variant_id": variant_id}]},
    )
    success = response.status_code == 201

    logger.info(f"{variant_id} was {'' if success else 'not '}purchased")

    return success


def download(session: requests.Session, variant_id: str) -> str:
    logger.info(f"Downloading {variant_id}...")

    response = session.get(f"https://mp-gateway.elgato.com/items/{variant_id}/direct-link")
    data = response.json()
    direct_link = data["direct_link"]
    response = session.get(direct_link)
    parsed = urlparse(direct_link)
    path = os.path.basename(parsed.path)

    with open(path, "wb") as f:
        f.write(response.content)

    logger.info(f"{variant_id} was downloaded to {path}")

    return path


def get_deploy_path(path: str, extension: str) -> str:
    logger.info("Getting deployment path...")

    roaming = os.getenv('APPDATA')
    deploy_path = f"{roaming}\\HotSpot\\StreamDock\\{extension}"

    logger.info(f"Deploying path is: {deploy_path}")

    return deploy_path


def unzip(path: str, deploy_path: str):
    logger.info(f"Unzipping {path} to {deploy_path}...")

    with zipfile.ZipFile(path, "r") as zip_ref:
        zip_ref.extractall(deploy_path)

    logger.info(f"{path} was unzipped to {deploy_path}")


def main(username: str, password: str, url: str, variant_name: str = None, deploy: bool = False) -> None:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    extension, variant_id = get_extension(url, variant_name)

    if not extension or not variant_id:
        return

    access_token = get_access_token(username, password)

    if not access_token:
        return

    session = get_session(access_token)

    if not is_purchased(session, variant_id):
        if not purchase(session, variant_id):
            return

    path = download(session, variant_id)

    if deploy:
        deploy_path = get_deploy_path(path, extension)
        unzip(path, deploy_path)


def cli():
    parser = argparse.ArgumentParser(description="Elgato extension downloader")
    parser.add_argument('-u', '--username', help='Elgato account username', default=DEFAULT_USERNAME)
    parser.add_argument('-p', '--password', help='Elgato account password', default=DEFAULT_PASSWORD)
    parser.add_argument('url', help='Elgato MarketPlace URL')
    parser.add_argument('variant', nargs='?', help='Content variant name (e.g. "Yellow"), defaults to default variant')
    parser.add_argument("-d", "--deploy", action="store_true", help="Deploy downloaded content to Stream Dock folder")
    args = parser.parse_args()
    main(args.username, args.password, args.url, args.variant, args.deploy)


if __name__ == '__main__':
    cli()
