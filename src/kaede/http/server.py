from enum import Enum
from typing import Optional, Union, Literal
from dataclasses import dataclass, field

from ..uds import UDS
from ..tcp import TCPPort
from ..udp import UDPPort
from ..tls import TLSServerConfig
from .models import HTTPVersion

class HTTPServerRole(Enum):
    ORIGIN = "Origin"
    PROXY = "Proxy"
    GATEWAY = "Gateway"
    TUNNEL = "Tunnel"

@dataclass
class HTTPServerPort:
    type: Literal["uds", "tcp", "quic"] = "tcp"
    port: Union[UDS, TCPPort, UDPPort] = TCPPort(80)
    secure: bool = False

    @property
    def vaild(self) -> bool:
        if self.type == "uds":
            return isinstance(self.port, UDS)
        elif self.type == "tcp":
            return isinstance(self.port, TCPPort)
        elif self.type == "quic":
            return isinstance(self.port, UDPPort) and self.secure

@dataclass
class HTTPServerConfig:
    versions: list[HTTPVersion] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]
    ports: list[HTTPServerPort] = field(default_factory=lambda: [HTTPServerPort(type="tcp", port=8080, secure=False)])
    tls: TLSServerConfig = field(default_factory=lambda: TLSServerConfig())

class HTTPServer:
    def __init__(self, config: Optional[HTTPServerConfig] = None, role: HTTPServerRole = HTTPServerRole.ORIGIN):
        self.role = role
        self.config = config or HTTPServerConfig()

    def run(self):
        ...

    async def serve(self):
        ...
