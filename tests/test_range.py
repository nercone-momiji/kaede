"""
Range request conformance tests (RFC 9110 §14 / RFC 7233).

Exercised through process_request with in-memory bodies. Tests assert the RFC,
including single ranges, suffix ranges, multipart/byteranges for multiple
ranges, 416 for unsatisfiable sets, If-Range, and that Range is ignored for
non-GET methods (RFC 9110 §14.2).
"""
from __future__ import annotations

import pytest

from kaede.models import Request, Response, Headers, Callback
from kaede.api.server import Config
from kaede.process import process_request, parse_ranges
from kaede.http.date import format_http_date
from datetime import datetime, timezone

BODY = b"0123456789"

class _Fixed(Callback):
    def __init__(self, response: Response):
        super().__init__()
        self._response = response

    async def on_request(self, request: Request) -> Response:
        return self._response

def make_response(**headers: str) -> Response:
    return Response(BODY, status_code=200, headers=Headers(headers), content_type="text/plain", compression=False)

def make_request(method: str = "GET", **headers: str) -> Request:
    return Request(method=method, target="/", headers=Headers(headers))

async def run(request: Request, response: Response | None = None) -> Response:
    return await process_request(request, _Fixed(response or make_response()), Config())

class TestParseRanges:
    def test_single(self):
        assert parse_ranges("bytes=0-4", 10) == [(0, 4)]

    def test_suffix(self):
        assert parse_ranges("bytes=-3", 10) == [(7, 9)]

    def test_open_ended(self):
        assert parse_ranges("bytes=5-", 10) == [(5, 9)]

    def test_unknown_unit_ignored(self):
        assert parse_ranges("items=0-4", 10) is None

    def test_malformed_ignored(self):
        assert parse_ranges("bytes=abc", 10) is None

    def test_last_before_first_invalid(self):
        assert parse_ranges("bytes=5-3", 10) is None

    def test_wholly_unsatisfiable_is_empty(self):
        assert parse_ranges("bytes=20-30", 10) == []

    def test_suffix_zero_unsatisfiable(self):
        assert parse_ranges("bytes=-0", 10) == []

    def test_skip_unsatisfiable_spec(self):
        # The set is satisfiable if at least one spec is (RFC 7233 §2.1).
        assert parse_ranges("bytes=0-1,50-60", 10) == [(0, 1)]

class TestSingleRange:
    async def test_partial_content(self):
        out = await run(make_request(Range="bytes=0-4"))
        assert out.status_code == 206
        assert out.body == b"01234"
        assert out.headers.get("Content-Range") == "bytes 0-4/10"

    async def test_suffix(self):
        out = await run(make_request(Range="bytes=-3"))
        assert out.status_code == 206
        assert out.body == b"789"
        assert out.headers.get("Content-Range") == "bytes 7-9/10"

class TestUnsatisfiable:
    async def test_416(self):
        out = await run(make_request(Range="bytes=20-30"))
        assert out.status_code == 416
        assert out.headers.get("Content-Range") == "bytes */10"
        assert out.headers.get("Content-Length") == "0"

class TestMultipart:
    async def test_multipart_byteranges(self):
        out = await run(make_request(Range="bytes=0-1,4-5"))
        assert out.status_code == 206
        ctype = out.headers.get("Content-Type")
        assert ctype.startswith("multipart/byteranges; boundary=")
        # No top-level Content-Range for a multipart response (RFC 7233 §4.1).
        assert out.headers.get("Content-Range") is None
        assert b"Content-Range: bytes 0-1/10" in out.body
        assert b"Content-Range: bytes 4-5/10" in out.body
        assert b"01" in out.body and b"45" in out.body

class TestIgnoredForNonGet:
    async def test_head_ignores_range(self):
        # RFC 9110 §14.2: range handling is defined for GET only.
        out = await run(make_request("HEAD", Range="bytes=0-4"))
        assert out.status_code == 200
        assert out.body is None

class TestIfRange:
    async def test_matching_etag_honors_range(self):
        out = await run(make_request(Range="bytes=0-4", **{"If-Range": '"v1"'}), make_response(ETag='"v1"'))
        assert out.status_code == 206

    async def test_non_matching_etag_serves_full(self):
        out = await run(make_request(Range="bytes=0-4", **{"If-Range": '"other"'}), make_response(ETag='"v1"'))
        assert out.status_code == 200
        assert out.body == BODY

    async def test_weak_etag_ignored(self):
        # RFC 7233 §3.2: a weak validator is never usable in If-Range.
        out = await run(make_request(Range="bytes=0-4", **{"If-Range": 'W/"v1"'}), make_response(ETag='W/"v1"'))
        assert out.status_code == 200

    async def test_matching_date_honors_range(self):
        lm = format_http_date(datetime(2024, 1, 1, tzinfo=timezone.utc))
        out = await run(make_request(Range="bytes=0-4", **{"If-Range": lm}), make_response(**{"Last-Modified": lm}))
        assert out.status_code == 206
