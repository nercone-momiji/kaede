"""
Conditional request conformance tests (RFC 9110 §13 / RFC 7232).

Exercised end-to-end through process_request for GET/HEAD. Tests assert the RFC
precedence and comparison rules, not Kaede's prior behavior.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from kaede.models import Request, Response, Headers, Callback
from kaede.api.server import Config
from kaede.process import process_request
from kaede.http.date import format_http_date

LAST_MOD = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
LAST_MOD_STR = format_http_date(LAST_MOD)

class _Fixed(Callback):
    def __init__(self, response: Response):
        super().__init__()
        self._response = response

    async def on_request(self, request: Request) -> Response:
        return self._response

def make_response(status: int = 200, etag: str | None = '"v1"', last_modified: str | None = LAST_MOD_STR) -> Response:
    headers = Headers({})
    if etag is not None:
        headers.set("ETag", etag)
    if last_modified is not None:
        headers.set("Last-Modified", last_modified)
    return Response(b"hello", status_code=status, headers=headers, content_type="text/plain")

def make_request(method: str = "GET", **header_kv: str) -> Request:
    return Request(method=method, target="/", headers=Headers(header_kv))

async def run(request: Request, response: Response) -> Response:
    return await process_request(request, _Fixed(response), Config())

class TestIfNoneMatch:
    async def test_matching_etag_returns_304(self):
        out = await run(make_request(**{"If-None-Match": '"v1"'}), make_response())
        assert out.status_code == 304
        assert out.body is None

    async def test_non_matching_returns_200(self):
        out = await run(make_request(**{"If-None-Match": '"other"'}), make_response())
        assert out.status_code == 200
        assert out.body == b"hello"

    async def test_star_matches_existing(self):
        out = await run(make_request(**{"If-None-Match": "*"}), make_response())
        assert out.status_code == 304

    async def test_weak_comparison(self):
        # RFC 7232 §3.2: If-None-Match uses weak comparison.
        out = await run(make_request(**{"If-None-Match": 'W/"v1"'}), make_response(etag='"v1"'))
        assert out.status_code == 304

    async def test_304_preserves_etag_and_drops_body_headers(self):
        out = await run(make_request(**{"If-None-Match": '"v1"'}), make_response())
        assert out.headers.get("ETag") == '"v1"'
        assert out.headers.get("Content-Type") is None
        assert out.headers.get("Content-Length") is None

class TestIfMatch:
    async def test_matching_proceeds(self):
        out = await run(make_request(**{"If-Match": '"v1"'}), make_response())
        assert out.status_code == 200

    async def test_non_matching_returns_412(self):
        out = await run(make_request(**{"If-Match": '"other"'}), make_response())
        assert out.status_code == 412
        assert out.body is None

    async def test_star_with_representation_proceeds(self):
        out = await run(make_request(**{"If-Match": "*"}), make_response())
        assert out.status_code == 200

    async def test_strong_comparison_rejects_weak_tag(self):
        # RFC 7232 §3.1: If-Match uses strong comparison; a weak tag never matches.
        out = await run(make_request(**{"If-Match": 'W/"v1"'}), make_response(etag='"v1"'))
        assert out.status_code == 412

    async def test_list_with_one_match(self):
        out = await run(make_request(**{"If-Match": '"a", "v1", "b"'}), make_response())
        assert out.status_code == 200

class TestIfModifiedSince:
    async def test_not_modified_returns_304(self):
        out = await run(make_request(**{"If-Modified-Since": LAST_MOD_STR}), make_response())
        assert out.status_code == 304

    async def test_modified_returns_200(self):
        earlier = format_http_date(LAST_MOD - timedelta(days=1))
        out = await run(make_request(**{"If-Modified-Since": earlier}), make_response())
        assert out.status_code == 200

    async def test_invalid_date_ignored(self):
        out = await run(make_request(**{"If-Modified-Since": "garbage"}), make_response())
        assert out.status_code == 200

class TestIfUnmodifiedSince:
    async def test_modified_returns_412(self):
        earlier = format_http_date(LAST_MOD - timedelta(days=1))
        out = await run(make_request(**{"If-Unmodified-Since": earlier}), make_response())
        assert out.status_code == 412

    async def test_unmodified_proceeds(self):
        out = await run(make_request(**{"If-Unmodified-Since": LAST_MOD_STR}), make_response())
        assert out.status_code == 200

class TestPrecedence:
    async def test_if_none_match_overrides_if_modified_since(self):
        # RFC 7232 §6 step 3/4: when If-None-Match is present and does not match,
        # If-Modified-Since is ignored and the method proceeds.
        out = await run(
            make_request(**{"If-None-Match": '"other"', "If-Modified-Since": LAST_MOD_STR}),
            make_response(),
        )
        assert out.status_code == 200

    async def test_if_match_overrides_if_unmodified_since(self):
        # If-Match present and passing means If-Unmodified-Since is not consulted.
        earlier = format_http_date(LAST_MOD - timedelta(days=1))
        out = await run(
            make_request(**{"If-Match": '"v1"', "If-Unmodified-Since": earlier}),
            make_response(),
        )
        assert out.status_code == 200

class TestScope:
    async def test_unsafe_method_not_auto_evaluated(self):
        # Kaede does not auto-evaluate preconditions for unsafe methods; the
        # callback's response is returned unchanged in status.
        out = await run(make_request("POST", **{"If-Match": '"other"'}), make_response())
        assert out.status_code == 200

    async def test_ignored_when_response_not_2xx(self):
        out = await run(make_request(**{"If-None-Match": '"v1"'}), make_response(status=404))
        assert out.status_code == 404
