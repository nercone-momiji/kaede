from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Union
from dataclasses import dataclass

class DNSRecordType(Enum):
    A          = 1
    AAAA       = 28
    AFSDB      = 18
    APL        = 42
    CAA        = 257
    CDNSKEY    = 60
    CDS        = 59
    CERT       = 37
    CNAME      = 5
    CSYNC      = 62
    DHCID      = 49
    DLV        = 32769
    DNAME      = 39
    DNSKEY     = 48
    DS         = 43
    EUI48      = 108
    EUI64      = 109
    HINFO      = 13
    HIP        = 55
    HTTPS      = 65
    IPSECKEY   = 45
    KEY        = 25
    KX         = 36
    LOC        = 29
    MX         = 15
    NAPTR      = 35
    NS         = 2
    NSEC       = 47
    NSEC3      = 50
    NSEC3PARAM = 51
    OPENPGPKEY = 61
    PTR        = 12
    RP         = 17
    RRSIG      = 46
    SIG        = 24
    SMIMEA     = 53
    SOA        = 6
    SRV        = 33
    SSHFP      = 44
    SVCB       = 64
    TA         = 32768
    TKEY       = 249
    TLSA       = 52
    TSIG       = 250
    TXT        = 16
    URI        = 256
    ZONEMD     = 63

    ANY        = 255
    AXFR       = 252
    IXFR       = 251
    OPT        = 41

class DNSRecordClass(Enum):
    IN = "Internet"
    CS = "CSNET"
    CH = "Chaosnet"
    HS = "Hesiod"

class DNSRecordData(ABC):
    @abstractmethod
    def pack(self) -> bytes:
        ...

    @classmethod
    @abstractmethod
    def unpack(cls, raw: bytes, message: bytes, offset: int) -> "DNSRecordData":
        ...

@dataclass(frozen=True, slots=True)
class DNSRecord:
    name: str
    type: DNSRecordType
    rclass: DNSRecordClass = DNSRecordClass.IN
    ttl: int = 0
    data: DNSRecordData

class DNSRecords:
    def __init__(self, value: Union[str, bytes, list[DNSRecord]]):
        if isinstance(value, (str, bytes)):
            self.raw = DNSRecords.parse(value).raw
        elif isinstance(value, list):
            self.raw = value
    ...
