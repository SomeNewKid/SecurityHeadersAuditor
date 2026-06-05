"""Command-line interface for Security Headers Auditor."""

from __future__ import annotations

import argparse
import sys
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from http.client import HTTPMessage
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import (
    parse_qsl,
    urldefrag,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)
from urllib.request import Request, urlopen

REQUIRED_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)

_GREEN = "\033[32m"
_RED = "\033[31m"
_RESET = "\033[0m"
_REQUEST_TIMEOUT_SECONDS = 10
_USER_AGENT = "SecurityHeadersAuditor/0.1"


@dataclass(frozen=True)
class _FetchResult:
    url: str
    headers: HTTPMessage
    content_type: str
    body: bytes


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "a":
            return

        for name, value in attrs:
            if name.lower() == "href" and value:
                self.links.append(value)


def main(argv: list[str] | None = None) -> int:
    """Run the Security Headers Auditor CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    start_url = _normalize_url(args.url)

    if start_url is None:
        parser.error("URL must use the HTTP or HTTPS scheme.")

    _crawl_and_audit(start_url)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crawl a website and audit required security headers.",
    )
    parser.add_argument("url", help="Starting website URL.")
    return parser


def _crawl_and_audit(start_url: str) -> None:
    start_hostname = _hostname(start_url)
    pending = deque([start_url])
    queued = {start_url}
    visited: set[str] = set()

    while pending:
        current_url = pending.popleft()

        if current_url in visited:
            continue

        visited.add(current_url)
        result = _fetch_url(current_url)

        if result is None:
            _print_failed_url(current_url, ["Unable to fetch URL"])
            continue

        _print_audit_result(result.url, result.headers)

        if not _is_html_response(result.content_type):
            continue

        links = _extract_links(result.body, result.content_type)
        for link in links:
            normalized_url = _normalize_url(link, result.url)

            if normalized_url is None:
                continue

            if _hostname(normalized_url) != start_hostname:
                continue

            if normalized_url in queued or normalized_url in visited:
                continue

            queued.add(normalized_url)
            pending.append(normalized_url)


def _fetch_url(url: str) -> _FetchResult | None:
    request = Request(url, headers={"User-Agent": _USER_AGENT})

    try:
        with urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            headers = cast(HTTPMessage, response.headers)
            content_type = headers.get("Content-Type", "")
            body = response.read()
            final_url = _normalize_url(response.geturl())
    except HTTPError as error:
        headers = cast(HTTPMessage, error.headers)
        content_type = headers.get("Content-Type", "")
        body = error.read()
        final_url = _normalize_url(error.geturl())
    except (OSError, URLError):
        return None

    if final_url is None:
        final_url = url

    return _FetchResult(final_url, headers, content_type, body)


def _print_audit_result(url: str, headers: HTTPMessage) -> None:
    missing_headers = _missing_headers(headers)
    color = _GREEN

    if missing_headers:
        color = _RED

    print(f"{color}{url}{_RESET}")

    if missing_headers:
        print(", ".join(missing_headers))


def _print_failed_url(url: str, messages: Iterable[str]) -> None:
    print(f"{_RED}{url}{_RESET}")
    print(", ".join(messages))


def _missing_headers(headers: HTTPMessage) -> list[str]:
    existing_headers = {header.lower() for header in headers.keys()}
    missing_headers = []

    for required_header in REQUIRED_HEADERS:
        if required_header.lower() not in existing_headers:
            missing_headers.append(required_header)

    return missing_headers


def _extract_links(body: bytes, content_type: str) -> list[str]:
    charset = _charset_from_content_type(content_type)
    html = body.decode(charset, errors="replace")
    parser = _LinkParser()
    parser.feed(html)
    return parser.links


def _charset_from_content_type(content_type: str) -> str:
    for part in content_type.split(";"):
        name, separator, value = part.strip().partition("=")

        if separator and name.lower() == "charset":
            return value.strip() or "utf-8"

    return "utf-8"


def _is_html_response(content_type: str) -> bool:
    media_type = content_type.split(";", maxsplit=1)[0]
    return media_type.strip().lower() == "text/html"


def _normalize_url(url: str, base_url: str | None = None) -> str | None:
    absolute_url = url

    if base_url is not None:
        absolute_url = urljoin(base_url, url)

    url_without_fragment, _fragment = urldefrag(absolute_url)
    parts = urlsplit(url_without_fragment)

    if parts.scheme.lower() not in {"http", "https"}:
        return None

    if not parts.hostname:
        return None

    scheme = parts.scheme.lower()
    hostname = parts.hostname.lower()
    netloc = _normalized_netloc(scheme, hostname, parts.port)
    path = parts.path or "/"
    query = _normalize_query(parts.query)

    return urlunsplit((scheme, netloc, path, query, ""))


def _normalized_netloc(scheme: str, hostname: str, port: int | None) -> str:
    if port is None:
        return hostname

    if scheme == "http" and port == 80:
        return hostname

    if scheme == "https" and port == 443:
        return hostname

    return f"{hostname}:{port}"


def _normalize_query(query: str) -> str:
    query_items = parse_qsl(query, keep_blank_values=True)
    return urlencode(query_items, doseq=True)


def _hostname(url: str) -> str:
    parts = urlsplit(url)
    hostname = parts.hostname

    if hostname is None:
        return ""

    return hostname.lower()


if __name__ == "__main__":
    sys.exit(main())
