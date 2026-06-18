from __future__ import annotations

# Generic HTTP field-value parsing helpers (RFC 9110 §5.6). These are shared by
# conditional requests, content negotiation, caching, cookies and Alt-Svc so the
# quoting rules are implemented once and correctly (e.g. a comma inside a
# quoted-string is data, not a list delimiter).

_TCHAR = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

def split_list(value: str) -> list[str]:
    """Split a comma-separated list (RFC 9110 §5.6.1 #rule), honoring
    quoted-strings so that commas inside DQUOTEs are not treated as separators.
    Empty elements are discarded, as permitted/required by the list rule."""
    if not value:
        return []

    elements: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False

    for ch in value:
        if in_quote:
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
            buf.append(ch)
        elif ch == ",":
            element = "".join(buf).strip()
            if element:
                elements.append(element)
            buf = []
        else:
            buf.append(ch)

    element = "".join(buf).strip()
    if element:
        elements.append(element)

    return elements

def unquote(value: str) -> str:
    """Remove DQUOTE delimiters and unescape quoted-pairs from a quoted-string
    (RFC 9110 §5.6.4). A bare token is returned unchanged."""
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return value

    out: list[str] = []
    i = 1
    end = len(value) - 1
    while i < end:
        ch = value[i]
        if ch == "\\" and i + 1 < end:
            out.append(value[i + 1])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)

def _split_semicolons(value: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    escaped = False

    for ch in value:
        if in_quote:
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
        elif ch == '"':
            in_quote = True
            buf.append(ch)
        elif ch == ";":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)

    parts.append("".join(buf))
    return parts

def parse_parameters(value: str) -> tuple[str, dict[str, str]]:
    """Parse "head ; name=value ; ..." (RFC 9110 §5.6.6). Returns the head token
    and an ordered dict of parameters. Parameter names are lowercased
    (case-insensitive); quoted values are unquoted; values keep their case."""
    segments = _split_semicolons(value)
    head = segments[0].strip()
    params: dict[str, str] = {}

    for seg in segments[1:]:
        seg = seg.strip()
        if not seg:
            continue
        name, eq, raw = seg.partition("=")
        name = name.strip().lower()
        if not name:
            continue
        params[name] = unquote(raw.strip()) if eq else ""

    return head, params

def parse_qvalue(raw: str) -> float:
    """Parse an RFC 9110 §12.4.2 qvalue, clamped to [0, 1]."""
    try:
        return max(0.0, min(1.0, float(raw)))
    except (ValueError, TypeError):
        return 0.0

def parse_qlist(value: str) -> list[tuple[str, float, dict[str, str]]]:
    """Parse an Accept-style list (RFC 9110 §12.4.2 / §12.5). Returns
    (member, q, params) tuples in the order received. The member token is
    lowercased; the "q" weight defaults to 1.0 and is excluded from params."""
    out: list[tuple[str, float, dict[str, str]]] = []

    for element in split_list(value):
        head, params = parse_parameters(element)
        head = head.lower()
        if not head:
            continue
        q = parse_qvalue(params["q"]) if "q" in params else 1.0
        params.pop("q", None)
        out.append((head, q, params))

    return out

def is_token(value: str) -> bool:
    """True if value is a non-empty RFC 9110 §5.6.2 token."""
    return bool(value) and all(ch in _TCHAR for ch in value)

# --- Entity tags (RFC 9110 §8.8.3 / RFC 7232 §2.3) -------------------------

def parse_entity_tag(value: str) -> tuple[bool, str] | None:
    """Parse one entity-tag. Returns (is_weak, opaque-tag-with-quotes) or None
    if not a valid entity-tag. The weak indicator "W/" is case-sensitive."""
    value = value.strip()
    weak = False
    if value.startswith("W/"):
        weak = True
        value = value[2:]
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return weak, value
    return None

def etag_strong_match(a: str, b: str) -> bool:
    """Strong comparison (RFC 9110 §8.8.3.2): equal only if neither is weak and
    the opaque-tags are identical character-by-character."""
    pa, pb = parse_entity_tag(a), parse_entity_tag(b)
    if pa is None or pb is None:
        return False
    return (not pa[0]) and (not pb[0]) and pa[1] == pb[1]

def etag_weak_match(a: str, b: str) -> bool:
    """Weak comparison (RFC 9110 §8.8.3.2): opaque-tags match regardless of the
    weakness flag of either tag."""
    pa, pb = parse_entity_tag(a), parse_entity_tag(b)
    if pa is None or pb is None:
        return False
    return pa[1] == pb[1]
