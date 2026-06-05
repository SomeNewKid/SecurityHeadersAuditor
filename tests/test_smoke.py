"""Tests for the Security Headers Auditor CLI."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import cast
from urllib.parse import urlsplit

from security_headers_auditor.cli import main

_REQUIRED_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


def test_cli_crawls_internal_pages_and_reports_headers(capsys) -> None:
    """Verify the CLI audits internal HTML pages discovered by crawling."""
    with _serve_test_site() as base_url:
        exit_code = main([base_url])

    output = capsys.readouterr().out

    assert exit_code == 0
    assert f"\033[32m{base_url}/\033[0m" in output
    assert f"\033[31m{base_url}/missing\033[0m" in output
    assert "Strict-Transport-Security, Content-Security-Policy" in output
    assert "/external" not in output
    assert "/mail" not in output


def test_cli_visits_equivalent_urls_once(capsys) -> None:
    """Verify fragments and repeated links do not cause duplicate audits."""
    with _serve_test_site() as base_url:
        main([f"{base_url}/"])

    output = capsys.readouterr().out

    assert output.count(f"{base_url}/missing") == 1


@contextmanager
def _serve_test_site() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TestHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = cast(tuple[str, int], server.server_address)
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class _TestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path

        if path == "/":
            self._send_html(
                """
                <a href="/missing#top">Missing</a>
                <a href="/missing">Duplicate</a>
                <a href="/missing?">Equivalent</a>
                <a href="mailto:test@example.com">Mail</a>
                <a href="javascript:void(0)">Script</a>
                <a href="https://example.com/external">External</a>
                """,
                include_all_headers=True,
            )
            return

        if path == "/missing":
            self._send_html("<a href='/'>Home</a>", include_all_headers=False)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_html(self, body: str, *, include_all_headers: bool) -> None:
        encoded_body = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded_body)))

        if include_all_headers:
            for name, value in _REQUIRED_HEADERS.items():
                self.send_header(name, value)
        else:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "geolocation=()")

        self.end_headers()
        self.wfile.write(encoded_body)
