from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs

@dataclass
class URL:
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str

    @classmethod
    def from_target(cls, target: str, scheme: str = "http", authority: str = "") -> URL:
        if "://" in target:
            return URL.parse_absolute(target)

        host, port = URL.parse_authority(authority)

        if target == "*":
            return cls(scheme=scheme, host=host, port=port, path="*", query="", fragment="")

        if not target.startswith("/"):
            conn_host, conn_port = URL.parse_authority(target)
            return cls(scheme=scheme, host=conn_host, port=conn_port, path="", query="", fragment="")

        path, _, qf = target.partition("?")
        query, _, fragment = qf.partition("#")
        if fragment:
            raise ValueError("request target must not contain a fragment identifier")
        return cls(scheme=scheme, host=host, port=port, path=path, query=query, fragment="")

    @classmethod
    def parse_absolute(cls, target: str) -> URL:
        scheme, _, rest = target.partition("://")
        authority_part, _, path_and_rest = rest.partition("/")
        path_and_rest = "/" + path_and_rest

        host, port = URL.parse_authority(authority_part)
        path, _, qf = path_and_rest.partition("?")
        query, _, fragment = qf.partition("#")
        if fragment:
            raise ValueError("request target must not contain a fragment identifier")
        return cls(scheme=scheme.lower(), host=host.lower(), port=port, path=path or "/", query=query, fragment="")

    @staticmethod
    def parse_authority(authority: str) -> tuple[str, int | None]:
        if not authority:
            return "", None

        if authority.startswith("["):
            bracket = authority.find("]")
            if bracket == -1:
                return authority, None

            host = authority[:bracket + 1]
            rest = authority[bracket + 1:]

            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    pass

            return host, None

        if ":" in authority:
            host, _, port_str = authority.rpartition(":")
            try:
                return host, int(port_str)
            except ValueError:
                pass

        return authority, None

    @property
    def params(self) -> dict[str, list[str]]:
        if not self.query:
            return {}
        return parse_qs(self.query, keep_blank_values=True)

    @property
    def netloc(self) -> str:
        if self.port is not None:
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def effective_port(self) -> int:
        if self.port is not None:
            return self.port
        return 443 if self.scheme == "https" else 80

    def __str__(self) -> str:
        if self.path == "*":
            return "*"

        if not self.path and self.port is not None:
            return f"{self.host}:{self.port}"

        result = f"{self.scheme}://{self.netloc}{self.path}"

        if self.query:
            result += f"?{self.query}"

        if self.fragment:
            result += f"#{self.fragment}"

        return result
