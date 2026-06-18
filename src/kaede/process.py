from __future__ import annotations

import os
import asyncio
import inspect
import traceback
import mimetypes
import email.utils

from typing import TYPE_CHECKING, Awaitable

from .models import Request, Response, Callback

if TYPE_CHECKING:
    from .api.client import Config as ClientConfig
    from .api.server import Config as ServerConfig

def parse_accept_encoding(accept_encoding: str) -> dict[str, float]:
    result: dict[str, float] = {}
    if not accept_encoding:
        return result

    for item in accept_encoding.split(","):
        token, _, params = item.strip().partition(";")
        token = token.strip().lower()
        if not token:
            continue

        q = 1.0
        for param in params.split(";"):
            param = param.strip()
            if param.startswith("q="):
                try:
                    q = max(0.0, min(1.0, float(param[2:])))
                except ValueError:
                    q = 0.0
                break

        result[token] = q

    return result

def parse_range(value: str, total: int) -> tuple[int, int] | None:
    if not value.startswith("bytes="):
        return None
    spec = value[6:].split(",")[0].strip()

    if spec.startswith("-"):
        try:
            suffix = int(spec[1:])
        except ValueError:
            return None
        if suffix <= 0 or total == 0:
            return None
        return (max(0, total - suffix), total - 1)

    dash = spec.find("-")
    if dash == -1:
        return None

    start_s, end_s = spec[:dash].strip(), spec[dash + 1:].strip()
    try:
        start = int(start_s)
    except ValueError:
        return None

    try:
        end = int(end_s) if end_s else total - 1
    except ValueError:
        return None

    if end >= total:
        end = total - 1

    if start > end or start >= total:
        return None

    return (start, end)

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
            request.decompress(content_encoding)
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
    response.headers.set("Content-Length", "0")

    try:
        if response.has_real_body:
            await response.minify(html=config.minify_html, css=config.minify_css, js=config.minify_js, svg=config.minify_svg, keep_html_comments=config.minify_keep_html_comments)

            range_header = request.headers.get("Range", "")
            if (range_header and request.method in ("GET", "HEAD") and response.status_code == 200):
                total = len(response.body)
                parsed = parse_range(range_header, total)

                response.headers.set("Accept-Ranges", "bytes")

                if parsed is None:
                    response.status_code = 416
                    response.headers.set("Content-Range", f"bytes */{total}")
                    response.body = b""
                    response.headers.set("Content-Length", "0")
                    return response

                start, end = parsed
                response.body = response.body[start:end + 1]
                response.status_code = 206
                response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")

            if response.status_code != 206:
                await response.compress(parse_accept_encoding(request.headers.get("Accept-Encoding", "")))

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.set("Content-Length", str(len(response.body)))

        elif response.is_streaming:
            await response.compress(parse_accept_encoding(request.headers.get("Accept-Encoding", "")))

            response.headers.set("Content-Type", response.content_type or response.headers.get("Content-Type") or "application/octet-stream")
            response.headers.remove("Content-Length")

            if request.protocol == "HTTP/1.1":
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

            range_header = request.headers.get("Range", "")
            if (range_header and request.method in ("GET", "HEAD") and response.status_code == 200):
                parsed = parse_range(range_header, total)
                if parsed is None:
                    response.status_code = 416
                    response.headers.set("Content-Range", f"bytes */{total}")
                    response.body = None
                    response.headers.set("Content-Length", "0")
                    return response

                start, end = parsed
                response.file_range = (start, end)
                response.status_code = 206
                response.headers.set("Content-Range", f"bytes {start}-{end}/{total}")
                response.headers.set("Content-Length", str(end - start + 1))

            else:
                await response.compress(parse_accept_encoding(request.headers.get("Accept-Encoding", "")))

                if response.has_real_body:
                    response.headers.remove("Accept-Ranges")
                    response.headers.set("Content-Length", str(len(response.body)))
                else:
                    response.headers.set("Content-Length", str(total))

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

        response.decompress(content_encoding)

        if response.body is None:
            response.body = response.compressed
            response.compressed = None

    elif isinstance(response.body, bytes):
        response.compressed = response.body
        response.body = None
        response.compression = True

        response.decompress(content_encoding)

        if response.body is not None:
            response.headers.set("Content-Length", str(len(response.body)))
        else:
            response.body = response.compressed
            response.compressed = None

    return response
