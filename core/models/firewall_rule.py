from dataclasses import dataclass
from typing import Optional

@dataclass
class FirewallRule:
    table: str
    chain: str
    protocol: Optional[str]
    src: Optional[str]
    dst: Optional[str]
    src_port: Optional[str]
    dst_port: Optional[str]
    in_iface: Optional[str]
    out_iface: Optional[str]
    action: str
    raw: str
    order: int
