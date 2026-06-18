from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .date import format_http_date

# RFC 6265: HTTP State Management Mechanism.

_TOKEN_CHARS = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
# cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E (no CTL, SP, DQUOTE, comma, semicolon, backslash)
_COOKIE_OCTETS = (
    {0x21}
    | set(range(0x23, 0x2C))
    | set(range(0x2D, 0x3B))
    | set(range(0x3C, 0x5C))
    | set(range(0x5D, 0x7F))
)

def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """Parse a request Cookie header (RFC 6265 §4.2.1) into (name, value) pairs.
    Surrounding DQUOTEs on a value are removed. Malformed pairs are skipped."""
    pairs: list[tuple[str, str]] = []
    if not value:
        return pairs

    for chunk in value.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        name, _, raw = chunk.partition("=")
        name = name.strip()
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
            raw = raw[1:-1]
        if name:
            pairs.append((name, raw))

    return pairs

@dataclass
class Cookie:
    name: str
    value: str
    expires: datetime | float | int | None = None
    max_age: int | None = None
    domain: str | None = None
    path: str | None = None
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None  # "Strict", "Lax", or "None"

    def serialize(self) -> str:
        """Serialize as a Set-Cookie field value (RFC 6265 §4.1.1)."""
        if not self.name or any(ch not in _TOKEN_CHARS for ch in self.name):
            raise ValueError("invalid cookie name")
        if any(ord(ch) not in _COOKIE_OCTETS for ch in self.value):
            raise ValueError("invalid cookie value")

        parts = [f"{self.name}={self.value}"]

        if self.expires is not None:
            parts.append("Expires=" + format_http_date(self.expires))
        if self.max_age is not None:
            parts.append(f"Max-Age={int(self.max_age)}")
        if self.domain:
            parts.append(f"Domain={self.domain}")
        if self.path:
            parts.append(f"Path={self.path}")
        if self.secure:
            parts.append("Secure")
        if self.http_only:
            parts.append("HttpOnly")
        if self.same_site:
            if self.same_site not in ("Strict", "Lax", "None"):
                raise ValueError("SameSite must be Strict, Lax, or None")
            # RFC 6265bis: SameSite=None is only meaningful with Secure.
            parts.append(f"SameSite={self.same_site}")

        return "; ".join(parts)

def parse_set_cookie(value: str) -> Cookie | None:
    """Parse a Set-Cookie field value (RFC 6265 §5.2). Returns None if the
    name-value pair is absent or empty."""
    if not value:
        return None

    head, _, rest = value.partition(";")
    if "=" not in head:
        return None

    name, _, cookie_value = head.partition("=")
    name = name.strip()
    cookie_value = cookie_value.strip()
    if not name:
        return None

    cookie = Cookie(name=name, value=cookie_value)

    for attribute in rest.split(";"):
        attribute = attribute.strip()
        if not attribute:
            continue
        attr_name, _, attr_value = attribute.partition("=")
        attr_name = attr_name.strip().lower()
        attr_value = attr_value.strip()

        if attr_name == "expires":
            from .date import parse_http_date
            cookie.expires = parse_http_date(attr_value)
        elif attr_name == "max-age":
            try:
                cookie.max_age = int(attr_value)
            except ValueError:
                pass
        elif attr_name == "domain":
            cookie.domain = attr_value.lstrip(".") or None
        elif attr_name == "path":
            cookie.path = attr_value or None
        elif attr_name == "secure":
            cookie.secure = True
        elif attr_name == "httponly":
            cookie.http_only = True
        elif attr_name == "samesite":
            normalized = attr_value.capitalize()
            if normalized in ("Strict", "Lax", "None"):
                cookie.same_site = normalized

    return cookie
