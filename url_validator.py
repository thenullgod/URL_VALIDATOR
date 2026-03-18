# -*- coding: utf-8 -*-
"""CLI helper that validates URLs before phishing analysis."""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

import certifi
import requests
from requests import RequestException

VALID_SCHEMES = {"http", "https"}


def is_valid_url(value: str) -> bool:
    """Return True if the string parses into an HTTP/HTTPS URL with a host."""
    try:
        parsed = urlparse(value.strip())
    except ValueError:
        return False

    return bool(parsed.scheme in VALID_SCHEMES and parsed.netloc)


def check_url_online(url: str) -> tuple[bool, str]:
    """Perform a HEAD request to ensure the URL resolves and returns a message."""
    try:
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=10,
            headers={"User-Agent": "url-detector/1.0"},
            verify=certifi.where(),
        )
        # Some servers reject HEAD; fall back to GET
        if response.status_code in {405, 501}:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=10,
                stream=True,
                headers={"User-Agent": "url-detector/1.0"},
                verify=certifi.where(),
            )
    except RequestException as exc:
        return False, f"network error: {exc}"

    if response.status_code >= 400:
        return False, f"HTTP {response.status_code}"

    scheme = urlparse(response.url if response.url else url).scheme
    notes: list[str] = []
    if scheme == "https":
        notes.append("TLS verified")
        if response.headers.get("strict-transport-security"):
            notes.append("HSTS enabled")
    else:
        notes.append("insecure scheme (HTTP)")

    if response.url:
        notes.append("resolved after redirects")

    return True, ", ".join(notes) or "OK"


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="url_detector",
        description="Check that a URL is syntactically valid and reachable.",
    )
    parser.add_argument(
        "url",
        help="A single HTTP or HTTPS URL to validate online.",
    )

    args = parser.parse_args()

    if not is_valid_url(args.url):
        parser.error("invalid URL syntax; choose http:// or https:// with a host")

    ok, message = check_url_online(args.url)
    prefix = "VALID" if ok else "INVALID"
    print(f"{prefix} {args.url} -> {message}")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
