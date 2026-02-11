from ipaddress import ip_network
from typing import Optional
import ipaddress



def ip_matches(a: Optional[str], b: Optional[str]) -> bool:
    """
    Return True if two IP specifications can match at least one common IP.
    None is treated as a wildcard.
    """
    if a is None or b is None:
        return True

    try:
        net_a = ip_network(a, strict=False)
        net_b = ip_network(b, strict=False)
        return net_a.overlaps(net_b)
    except ValueError:
        return False

def networks_overlap(a: Optional[str], b: Optional[str]) -> bool:
    """
    Alias used by conflict detection.
    """
    return ip_matches(a, b)

def ip_overlap(net1: ipaddress.IPv4Network, net2: ipaddress.IPv4Network) -> bool:
    """
    Return True if net1 and net2 overlap in any addresses.
    Works even if one network is fully contained in the other.
    """
    return net1.overlaps(net2)