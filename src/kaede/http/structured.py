from __future__ import annotations

import base64
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_EVEN

class StructuredFieldError(ValueError):
    pass

class Token(str):
    __slots__ = ()

BareItem = "int | Decimal | str | Token | bytes | bool"

@dataclass
class Item:
    value: object
    params: dict[str, object] = field(default_factory=dict)

@dataclass
class InnerList:
    items: list[Item] = field(default_factory=list)
    params: dict[str, object] = field(default_factory=dict)

TCHAR = set("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
LCALPHA = set("abcdefghijklmnopqrstuvwxyz")
DIGITS = set("0123456789")
KEY_CHARS = LCALPHA | DIGITS | set("_-.*")
B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

class _Parser:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)

    def skip_sp(self):
        while self.i < self.n and self.s[self.i] == " ":
            self.i += 1

    def skip_ows(self):
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1

    def parse_list(self) -> list:
        members: list = []
        while self.i < self.n:
            members.append(self.parse_item_or_inner_list())
            self.skip_ows()

            if self.i >= self.n:
                return members

            if self.s[self.i] != ",":
                raise StructuredFieldError("expected comma in list")

            self.i += 1
            self.skip_ows()

            if self.i >= self.n:
                raise StructuredFieldError("trailing comma in list")

        return members

    def parse_dictionary(self) -> dict:
        out: dict = {}
        while self.i < self.n:
            key = self.parse_key()

            if self.i < self.n and self.s[self.i] == "=":
                self.i += 1
                member = self.parse_item_or_inner_list()
            else:
                member = Item(True, self.parse_parameters())

            out[key] = member
            self.skip_ows()

            if self.i >= self.n:
                return out

            if self.s[self.i] != ",":
                raise StructuredFieldError("expected comma in dictionary")

            self.i += 1
            self.skip_ows()

            if self.i >= self.n:
                raise StructuredFieldError("trailing comma in dictionary")

        return out

    def parse_item_or_inner_list(self) -> Item | InnerList:
        if self.i < self.n and self.s[self.i] == "(":
            return self.parse_inner_list()
        return self.parse_item()

    def parse_inner_list(self) -> InnerList:
        if self.i >= self.n or self.s[self.i] != "(":
            raise StructuredFieldError("expected inner list")

        self.i += 1
        items: list[Item] = []

        while self.i < self.n:
            self.skip_sp()

            if self.i < self.n and self.s[self.i] == ")":
                self.i += 1
                return InnerList(items, self.parse_parameters())

            items.append(self.parse_item())

            if self.i < self.n and self.s[self.i] not in " )":
                raise StructuredFieldError("expected SP or ) in inner list")

        raise StructuredFieldError("unterminated inner list")

    def parse_item(self) -> Item:
        value = self.parse_bare_item()
        return Item(value, self.parse_parameters())

    def parse_bare_item(self):
        if self.i >= self.n:
            raise StructuredFieldError("empty bare item")
        c = self.s[self.i]
        if c == "-" or c in DIGITS:
            return self.parse_integer_or_decimal()
        if c == '"':
            return self.parse_string()
        if c.isalpha() or c == "*":
            return self.parse_token()
        if c == ":":
            return self.parse_byte_sequence()
        if c == "?":
            return self.parse_boolean()
        raise StructuredFieldError(f"unrecognized bare item: {c!r}")

    def parse_parameters(self) -> dict:
        params: dict = {}
        while self.i < self.n and self.s[self.i] == ";":
            self.i += 1
            self.skip_sp()

            key = self.parse_key()
            value: object = True
            if self.i < self.n and self.s[self.i] == "=":
                self.i += 1
                value = self.parse_bare_item()

            params[key] = value

        return params

    def parse_key(self) -> str:
        if self.i >= self.n or (self.s[self.i] not in LCALPHA and self.s[self.i] != "*"):
            raise StructuredFieldError("invalid key start")
        start = self.i
        while self.i < self.n and self.s[self.i] in KEY_CHARS:
            self.i += 1
        return self.s[start:self.i]

    def parse_integer_or_decimal(self):
        kind = "integer"
        sign = 1

        if self.s[self.i] == "-":
            sign = -1
            self.i += 1

        if self.i >= self.n or self.s[self.i] not in DIGITS:
            raise StructuredFieldError("empty integer")

        num = ""
        while self.i < self.n:
            c = self.s[self.i]

            if c in DIGITS:
                num += c
                self.i += 1

            elif kind == "integer" and c == ".":
                if len(num) > 12:
                    raise StructuredFieldError("too many integer digits before decimal")

                num += c
                kind = "decimal"
                self.i += 1

            else:
                break

            if kind == "integer" and len(num) > 15:
                raise StructuredFieldError("integer too long")

            if kind == "decimal" and len(num) > 16:
                raise StructuredFieldError("decimal too long")

        if kind == "integer":
            return sign * int(num)

        if num.endswith("."):
            raise StructuredFieldError("decimal ends with dot")

        if len(num) - num.index(".") - 1 > 3:
            raise StructuredFieldError("too many fractional digits")

        return Decimal(num) * sign

    def parse_string(self) -> str:
        if self.s[self.i] != '"':
            raise StructuredFieldError("expected string")

        self.i += 1
        out: list[str] = []

        while self.i < self.n:
            c = self.s[self.i]
            self.i += 1

            if c == "\\":
                if self.i >= self.n:
                    raise StructuredFieldError("trailing backslash in string")

                nxt = self.s[self.i]
                self.i += 1

                if nxt not in ('"', "\\"):
                    raise StructuredFieldError("invalid escape in string")

                out.append(nxt)

            elif c == '"':
                return "".join(out)

            elif ord(c) < 0x20 or ord(c) > 0x7E:
                raise StructuredFieldError("invalid character in string")

            else:
                out.append(c)

        raise StructuredFieldError("unterminated string")

    def parse_token(self) -> Token:
        start = self.i
        self.i += 1

        while self.i < self.n and (self.s[self.i] in TCHAR or self.s[self.i] in ":/"):
            self.i += 1

        return Token(self.s[start:self.i])

    def parse_byte_sequence(self) -> bytes:
        if self.s[self.i] != ":":
            raise StructuredFieldError("expected byte sequence")

        self.i += 1
        end = self.s.find(":", self.i)

        if end == -1:
            raise StructuredFieldError("unterminated byte sequence")

        b64 = self.s[self.i:end]
        self.i = end + 1

        if any(ch not in B64_CHARS for ch in b64):
            raise StructuredFieldError("invalid base64 in byte sequence")

        padded = b64 + "=" * (-len(b64) % 4)
        try:
            return base64.b64decode(padded)
        except Exception as exc:
            raise StructuredFieldError("base64 decode failed") from exc

    def parse_boolean(self) -> bool:
        if self.s[self.i] != "?":
            raise StructuredFieldError("expected boolean")

        self.i += 1
        if self.i < self.n and self.s[self.i] == "1":
            self.i += 1
            return True

        if self.i < self.n and self.s[self.i] == "0":
            self.i += 1
            return False

        raise StructuredFieldError("invalid boolean")

def parse(value: str | bytes, field_type: str):
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise StructuredFieldError("field value is not ASCII") from exc

    p = _Parser(value)
    p.skip_sp()

    if field_type == "list":
        output = p.parse_list()
    elif field_type == "dictionary":
        output = p.parse_dictionary()
    elif field_type == "item":
        output = p.parse_item()
    else:
        raise StructuredFieldError(f"unknown field type: {field_type}")

    p.skip_sp()
    if p.i != p.n:
        raise StructuredFieldError("trailing characters after value")

    return output

def ser_key(key: str) -> str:
    if not key or (key[0] not in LCALPHA and key[0] != "*"):
        raise StructuredFieldError("invalid key")
    if any(ch not in KEY_CHARS for ch in key):
        raise StructuredFieldError("invalid key character")
    return key

def ser_integer(value: int) -> str:
    if not (-999_999_999_999_999 <= value <= 999_999_999_999_999):
        raise StructuredFieldError("integer out of range")
    return str(value)

def ser_decimal(value: Decimal | float) -> str:
    d = value if isinstance(value, Decimal) else Decimal(str(value))
    d = d.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
    neg = d < 0
    text = format(abs(d), "f")
    if "." not in text:
        text += ".0"
    int_part, frac = text.split(".")
    if len(int_part) > 12:
        raise StructuredFieldError("decimal integer part too long")
    frac = frac.rstrip("0") or "0"
    return ("-" if neg else "") + int_part + "." + frac

def ser_string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) > 0x7E:
            raise StructuredFieldError("invalid character in string")
        if ch in ('"', "\\"):
            out.append("\\")
        out.append(ch)
    out.append('"')
    return "".join(out)

def ser_token(value: str) -> str:
    if not value or (not value[0].isalpha() and value[0] != "*"):
        raise StructuredFieldError("invalid token")
    if any(ch not in TCHAR and ch not in ":/" for ch in value[1:]):
        raise StructuredFieldError("invalid token character")
    return value

def ser_byte_sequence(value: bytes) -> str:
    return ":" + base64.b64encode(value).decode("ascii") + ":"

def ser_bare_item(value) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, Token):
        return ser_token(value)
    if isinstance(value, int):
        return ser_integer(value)
    if isinstance(value, Decimal) or isinstance(value, float):
        return ser_decimal(value)
    if isinstance(value, str):
        return ser_string(value)
    if isinstance(value, (bytes, bytearray)):
        return ser_byte_sequence(bytes(value))
    raise StructuredFieldError(f"cannot serialize bare item of type {type(value).__name__}")

def ser_parameters(params: dict) -> str:
    out: list[str] = []
    for key, val in params.items():
        out.append(";" + ser_key(key))
        if val is not True:
            out.append("=" + ser_bare_item(val))
    return "".join(out)

def as_item_or_inner_list(member):
    if isinstance(member, (Item, InnerList)):
        return member
    return Item(member, {})

def ser_item(item: Item) -> str:
    return ser_bare_item(item.value) + ser_parameters(item.params)

def ser_inner_list(inner: InnerList) -> str:
    parts = [ser_item(as_item_or_inner_list(it)) for it in inner.items]
    return "(" + " ".join(parts) + ")" + ser_parameters(inner.params)

def ser_member(member) -> str:
    member = as_item_or_inner_list(member)
    if isinstance(member, InnerList):
        return ser_inner_list(member)
    return ser_item(member)

def serialize_item(item) -> str:
    return ser_member(as_item_or_inner_list(item))

def serialize_list(members: list) -> str:
    return ", ".join(ser_member(m) for m in members)

def serialize_dictionary(dictionary: dict) -> str:
    out: list[str] = []

    for key, member in dictionary.items():
        member = as_item_or_inner_list(member)

        if isinstance(member, Item) and member.value is True:
            out.append(ser_key(key) + ser_parameters(member.params))
        else:
            out.append(ser_key(key) + "=" + ser_member(member))

    return ", ".join(out)

def serialize(value) -> str:
    if isinstance(value, dict):
        return serialize_dictionary(value)
    if isinstance(value, list):
        return serialize_list(value)
    return serialize_item(value)
