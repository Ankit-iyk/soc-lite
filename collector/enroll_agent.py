"""Enroll this collector and store its scoped token with Windows DPAPI."""

import base64
import getpass
import json
import os
import platform
from pathlib import Path

import requests
import win32crypt

from state import validate_api_url


def main():
    config_path = Path(os.environ.get("SOC_LITE_COLLECTOR_CONFIG", Path(__file__).with_name("config.json")))
    with config_path.open("r", encoding="utf-8") as config_file:
        config = json.load(config_file)
    api_url = validate_api_url(config.get("api_url", ""))

    email = input("SOC Lite admin email: ").strip()
    password = getpass.getpass("SOC Lite admin password (input hidden): ")
    session = requests.Session()

    login_response = session.post(
        f"{api_url}/auth/login",
        json={"email": email, "password": password},
        timeout=15,
    )
    login_response.raise_for_status()
    login_result = login_response.json()
    if not login_result.get("success") or not login_result.get("data", {}).get("token"):
        raise RuntimeError("The SOC Lite login response was invalid")

    enrollment_response = session.post(
        f"{api_url}/collectors/tokens",
        headers={"Authorization": f"Bearer {login_result['data']['token']}"},
        json={"name": platform.node()},
        timeout=15,
    )
    enrollment_response.raise_for_status()
    enrollment = enrollment_response.json()
    token = enrollment.get("data", {}).get("rawToken")
    if not enrollment.get("success") or not token:
        raise RuntimeError("The SOC Lite enrollment response was invalid")

    protected = win32crypt.CryptProtectData(
        token.encode("utf-8"),
        "SOC Lite collector token",
        None,
        None,
        None,
        0,
    )
    encrypted = protected[1] if isinstance(protected, tuple) else protected
    token_path = Path(os.environ.get("SOC_LITE_COLLECTOR_TOKEN_FILE", Path(__file__).with_name("token.dpapi")))
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_bytes(base64.b64encode(encrypted))
    print(f"Collector {platform.node()} enrolled; its credential is DPAPI-protected at {token_path}.")


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as error:
        response = error.response
        status = response.status_code if response is not None else "unknown"
        detail = "No server error message available."

        if response is not None:
            try:
                body = response.json()
                if isinstance(body, dict):
                    detail = str(
                        body.get("message")
                        or body.get("error")
                        or detail
                    )
            except ValueError:
                pass

        raise SystemExit(
            f"Collector enrollment failed: HTTP {status}. {detail}"
        ) from None
    except (
        OSError,
        ValueError,
        RuntimeError,
        requests.RequestException,
    ) as error:
        raise SystemExit(
            f"Collector enrollment failed ({type(error).__name__}). "
            "Check configuration and API availability."
        ) from None