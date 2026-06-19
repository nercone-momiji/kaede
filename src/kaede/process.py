from __future__ import annotations

import os
import asyncio
import inspect
import traceback
import mimetypes
import email.utils

from typing import TYPE_CHECKING, Awaitable

from .models import Request, Response, Headers, Callback
from .http.fields import parse_qlist, split_list, etag_strong_match, etag_weak_match
from .http.date import parse_http_date

if TYPE_CHECKING:
    from .api.client import Config as ClientConfig
    from .api.server import Config as ServerConfig

NOT_MODIFIED_HEADERS = frozenset({"cache-control", "content-location", "date", "etag", "expires", "vary", "last-modified", "server",})

def if_match_passes(field_value: str, etag: str) -> bool:
    value = field_value.strip()

    if value == "*":
        return True

    if not etag:
        return False

    return any(etag_strong_match(tag, etag) for tag in split_list(value))

def if_none_match_matches(field_value: str, etag: str) -> bool:
    value = field_value.strip()

    if value == "*":
        return True

    if not etag:
        return False

    return any(etag_weak_match(tag, etag) for tag in split_list(value))

def not_modified(response: Response) -> Response:
    filtered = Headers({})
    for key, values in response.headers.headers.items():
        if key in NOT_MODIFIED_HEADERS:
            for value in values:
                filtered.append(key, value)

    response.headers = filtered
    response.status_code = 304
    response.body = None
    response.compressed = None
    return response

def precondition_failed(response: Response) -> Response:
    for header in ("Content-Type", "Content-Encoding", "Transfer-Encoding", "Content-Range", "Accept-Ranges"):
        response.headers.remove(header)

    response.status_code = 412
    response.body = None
    response.compressed = None
    response.headers.set("Content-Length", "0")
    return response

def evaluate_preconditions(request: Request, response: Response) -> Response | None:
    if request.method not in ("GET", "HEAD"):
        return None

    if response.status_code != 200:
        return None

    etag = (response.headers.get("ETag") or "").strip()
    last_modified_raw = (response.headers.get("Last-Modified") or "").strip()
    last_modified = parse_http_date(last_modified_raw) if last_modified_raw else None

    if_match = request.headers.get("If-Match")
    if_unmodified_since = request.headers.get("If-Unmodified-Since")
    if_none_match = request.headers.get("If-None-Match")
    if_modified_since = request.headers.get("If-Modified-Since")

    if if_match is not None:
        if not if_match_passes(if_match, etag):
            return precondition_failed(response)

    elif if_unmodified_since is not None:
        when = parse_http_date(if_unmodified_since)
        if when is not None and last_modified is not None and last_modified > when:
            return precondition_failed(response)

    if if_none_match is not None:
        if if_none_match_matches(if_none_match, etag):
            return not_modified(response)
        return None

    if if_modified_since is not None:
        when = parse_http_date(if_modified_since)
        if when is not None and last_modified is not None and last_modified <= when:
            return not_modified(response)

    return None

def parse_accept_encoding(accept_encoding: str) -> dict[str, float]:
    result: dict[str, float] = {}

    for token, q, _ in parse_qlist(accept_encoding or ""):
        result[token] = q

    return result

def parse_one_range(spec: str, total: int) -> tuple[int, int] | str:
    if spec.startswith("-"):
        if not spec[1:].isdigit():
            return "invalid"

        suffix = int(spec[1:])

        if suffix == 0 or total == 0:
            return "unsatisfiable"

        return (max(0, total - suffix), total - 1)

    dash = spec.find("-")
    if dash == -1:
        return "invalid"

    start_s, end_s = spec[:dash].strip(), spec[dash + 1:].strip()
    if not start_s.isdigit():
        return "invalid"
    start = int(start_s)

    if end_s:
        if not end_s.isdigit():
            return "invalid"
        end = int(end_s)
        if end < start:
            return "invalid"
    else:
        end = total - 1

    if start >= total:
        return "unsatisfiable"
    if end >= total:
        end = total - 1

    return (start, end)

def parse_ranges(value: str, total: int) -> list[tuple[int, int]] | None:
    if not value.startswith("bytes="):
        return None

    ranges: list[tuple[int, int]] = []
    saw_spec = False

    for spec in value[6:].split(","):
        spec = spec.strip()
        if not spec:
            continue

        saw_spec = True

        parsed = parse_one_range(spec, total)
        if parsed == "invalid":
            return None
        if parsed == "unsatisfiable":
            continue

        ranges.append(parsed)

    if not saw_spec:
        return None

    return ranges

def build_multipart_byteranges(parts: list[tuple[int, int, bytes]], total: int, content_type: str) -> tuple[bytes, str]:
    boundary = os.urandom(16).hex()
    crlf = b"\r\n"
    out = bytearray()

    for start, end, data in parts:
        out += b"--" + boundary.encode("ascii") + crlf
        out += b"Content-Type: " + content_type.encode("latin-1") + crlf
        out += f"Content-Range: bytes {start}-{end}/{total}".encode("ascii") + crlf
        out += crlf
        out += data + crlf

    out += b"--" + boundary.encode("ascii") + b"--" + crlf
    return bytes(out), f"multipart/byteranges; boundary={boundary}"

def effective_range(request: Request, response: Response) -> str:
    range_header = request.headers.get("Range", "") or ""
    if not range_header:
        return ""

    if_range = (request.headers.get("If-Range") or "").strip()
    if not if_range:
        return range_header

    etag = (response.headers.get("ETag") or "").strip()
    last_modified = (response.headers.get("Last-Modified") or "").strip()

    if if_range.startswith("W/"):
        return ""
    if if_range.startswith('"'):
        return range_header if etag and etag_strong_match(if_range, etag) else ""

    when = parse_http_date(if_range)
    lm = parse_http_date(last_modified) if last_modified else None
    return range_header if (when is not None and lm is not None and when == lm) else ""

def error_response(request: Request, config: ServerConfig) -> Response:
    response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False)

    response.headers.set("Date", email.utils.formatdate(usegmt=True), override=False)
    response.headers.set("Server", config.server_name, override=False)
    response.headers.set("Content-Type", "text/plain; charset=utf-8")
    response.headers.set("Content-Length", str(len(response.body)))

    if request.method == "HEAD":
        response.body = None

    return response

async def process_request(request: Request, callback: Callback, config: ServerConfig, response: Response | None = None) -> Response:
    content_encoding = (request.headers.get("Content-Encoding") or "").strip()
    if content_encoding and isinstance(request.body, bytes):
        request.compressed = request.body
        request.body = None

        try:
            request.decompress(content_encoding, max_size=config.max_body_size)
        except Exception:
            pass

        if request.body is not None:
            request.headers.set("Content-Length", str(len(request.body)))
        else:
            request.body = request.compressed
            request.compressed = None

    if not response:
        try:
            response: Response | Awaitable[Response] = callback.on_request(request)
            if inspect.isawaitable(response):
                response = await response

        except Exception:
            traceback.print_exc()
            response = Response(b"Internal Server Error", status_code=500, compression=False, minification=False)

    response.headers.set("Date", email.utils.formatdate(usegmt=True), override=False)
    response.headers.set("Server", config.server_name, override=False)

    conditional = evaluate_preconditions(request, response)
    if conditional is not None:
        if request.method == "HEAD":
            conditional.body = None
        return conditional

    try:
        if response.has_real_body:
            await response.minify(html=config.minify_html, css=config.minify_css, js=config.minify_js, svg=config.minify_svg, keep_html_comments=config.minify_keep_html_comments)

            if response.status_code == 200 and request.method == "GET":
                response.headers.set("Accept-Ranges", "bytes", override=False)

            range_header = effective_range(request, response) if request.method == "GET" and response.status_code == 200 else ""

            if range_header:
                total = len(response.body)
                ranges = parse_ranges(range_header, total)

                if ranges is not None and not ranges:
                    response.status_code = 416
                    response.headers.set("Content-Range", f"bytes */{total}")
                    response.headers.remove("Content-Encoding")
                    response.body = b""
                    response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
                    response.headers.set("Content-Length", "0")
                    return response

                if ranges and len(ranges) == 1:
                    start, end = ranges[0]
                    response.body = response.body[start:end + 1]
                    response.status_code = 206
                    response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")

                elif ranges:
                    representation_type = response.content_type or response.headers.get("Content-Type") or "application/octet-stream"
                    body, ctype = build_multipart_byteranges([(s, e, response.body[s:e + 1]) for s, e in ranges], total, representation_type)
                    response.body = body
                    response.content_type = ctype
                    response.headers.remove("Content-Range")
                    response.status_code = 206

            if response.status_code != 206:
                await response.compress(parse_accept_encoding(request.headers.get("Accept-Encoding", "")))

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.set("Content-Length", str(len(response.body)))

        elif response.is_streaming:
            await response.compress(parse_accept_encoding(request.headers.get("Accept-Encoding", "")))

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.remove("Content-Length")

            if request.protocol == "HTTP/1.1" and not (100 <= response.status_code < 200 or response.status_code in (204, 205, 304)):
                response.headers.set("Transfer-Encoding", "chunked")

        elif response.body is not None:
            loop = asyncio.get_running_loop()
            path = os.fspath(response.body)

            try:
                mime, _ = mimetypes.guess_type(path)
            except OSError:
                mime = None

            total = await loop.run_in_executor(None, os.path.getsize, path)

            response.headers.set("Accept-Ranges", "bytes")
            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or mime or "application/octet-stream")

            range_header = effective_range(request, response) if request.method == "GET" and response.status_code == 200 else ""
            ranges = parse_ranges(range_header, total) if range_header else None

            if range_header and ranges is not None and not ranges:
                response.status_code = 416
                response.headers.set("Content-Range", f"bytes */{total}")
                response.body = None
                response.headers.set("Content-Length", "0")
                return response

            if ranges and len(ranges) == 1:
                start, end = ranges[0]
                response.file_range = (start, end)
                response.status_code = 206
                response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")
                response.headers.set("Content-Length", str(end - start + 1))

            elif ranges:
                representation_type = response.headers.get("Content-Type") or mime or "application/octet-stream"

                def read_slices(path_str=path, specs=ranges):
                    chunks: list[bytes] = []
                    with open(path_str, "rb") as fh:
                        for s, e in specs:
                            fh.seek(s)
                            chunks.append(fh.read(e - s + 1))
                    return chunks

                slices = await loop.run_in_executor(None, read_slices)
                body, ctype = build_multipart_byteranges([(ranges[i][0], ranges[i][1], slices[i]) for i in range(len(ranges))], total, representation_type)

                response.body = body
                response.file_range = None
                response.content_type = ctype
                response.headers.set("Content-Type", ctype)
                response.status_code = 206
                response.headers.set("Content-Length", str(len(body)))

            else:
                await response.compress(parse_accept_encoding(request.headers.get("Accept-Encoding", "")))

                if response.has_real_body:
                    response.headers.remove("Accept-Ranges")
                    response.headers.set("Content-Length", str(len(response.body)))
                else:
                    response.headers.set("Content-Length", str(total))

        else:
            response.headers.set("Content-Length", "0")

        if (response.has_real_body or response.is_streaming) and response.headers.get("Content-Type", "").startswith("text/") and "charset=" not in response.headers.get("Content-Type", ""):
            response.headers.set("Content-Type", response.headers.get("Content-Type", "") + "; charset=utf-8")

    except Exception:
        traceback.print_exc()
        return error_response(request, config)

    if request.method == "HEAD":
        if response.is_streaming:
            response.headers.remove("Transfer-Encoding")
            if hasattr(response.body, "aclose"):
                try:
                    await response.body.aclose()
                except Exception:
                    pass

        response.body = None

    return response

async def process_response(response: Response, config: ClientConfig) -> Response:
    if not config.decompress:
        return response

    content_encoding = (response.headers.get("Content-Encoding") or "").strip()
    if not content_encoding:
        return response

    if response.is_streaming:
        response.compressed = response.body
        response.body = None
        response.compression = True

        response.decompress(content_encoding, max_size=config.max_body_size)

        if response.body is None:
            response.body = response.compressed
            response.compressed = None

    elif isinstance(response.body, bytes):
        response.compressed = response.body
        response.body = None
        response.compression = True

        response.decompress(content_encoding, max_size=config.max_body_size)

        if response.body is not None:
            response.headers.set("Content-Length", str(len(response.body)))
        else:
            response.body = response.compressed
            response.compressed = None

    return response
