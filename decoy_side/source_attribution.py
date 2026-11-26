"""
BAITSCOPE — Real Source IP Attribution & Network Provenance Module
Zero-Spoof Network Connection Peer Extraction, RFC 7239 / Proxy Chain Traversal,
Canonical IP Normalization, and Provenance Status Classification.
"""

import os
import datetime
import ipaddress
from dataclasses import dataclass, asdict
from typing import Optional, Tuple, List, Dict, Any

@dataclass
class SourceAttribution:
    """Structured network source provenance container."""
    peer_ip: str
    client_ip: str
    ip_version: str
    attribution_method: str    # "direct_peer" | "trusted_proxy_chain" | "remote_node"
    attribution_status: str    # "verified_peer" | "proxy_attributed" | "unverified_historical" | "remote_node_forwarded"
    is_forwarded: bool
    is_synthetic: bool
    observed_at: datetime.datetime
    raw_forwarded_for: Optional[str] = None
    raw_real_ip: Optional[str] = None
    proxy_hops_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["observed_at"] = self.observed_at.isoformat()
        return d


def normalize_ip_address(ip_str: str) -> Tuple[str, str]:
    """
    Validates and canonicalizes IPv4 and IPv6 addresses.
    Strips ports from IPv4 (192.168.1.1:8080) and bracketed IPv6 ([2001:db8::1]:443).
    Unmaps IPv4-mapped IPv6 (::ffff:192.0.2.1 -> 192.0.2.1).

    Returns:
        (canonical_ip_str, "IPv4" | "IPv6")
    Raises:
        ValueError if string is not a valid IP.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError("Invalid empty or non-string IP address")
    
    clean = ip_str.strip()
    if not clean:
        raise ValueError("Empty IP string")

    # Strip port if present in bracketed IPv6 (e.g. [2001:db8::1]:443)
    if clean.startswith("[") and "]" in clean:
        clean = clean.split("]")[0].strip("[")
    elif ":" in clean and "." in clean and clean.count(":") == 1:
        # IPv4 with port (e.g. 192.168.1.10:54321)
        clean = clean.split(":")[0]

    addr = ipaddress.ip_address(clean)
    if hasattr(addr, "ipv4_mapped") and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    version = f"IPv{addr.version}"
    return (str(addr), version)


def get_configured_trusted_proxies() -> List[ipaddress._BaseNetwork]:
    """
    Parses BAITSCOPE_TRUSTED_PROXIES (or legacy SENTINEL_TRUSTED_PROXIES) environment variable into ip_network objects.
    Returns empty list if unset, empty, or set to 'none'/'false'/'disabled'.
    """
    raw = os.getenv("BAITSCOPE_TRUSTED_PROXIES") or os.getenv("SENTINEL_TRUSTED_PROXIES")
    if raw is None:
        return []
    raw = raw.strip()
    if not raw or raw.lower() in ["none", "disabled", "false"]:
        return []
    
    networks = []
    for item in raw.split(","):
        clean = item.strip()
        if not clean:
            continue
        try:
            net = ipaddress.ip_network(clean, strict=False)
            networks.append(net)
        except ValueError:
            pass
    return networks


def is_trusted_proxy(peer_ip_str: str) -> bool:
    """
    Determines if the direct TCP peer address belongs to a configured trusted reverse proxy.
    """
    if not peer_ip_str:
        return False
    try:
        peer_addr = ipaddress.ip_address(peer_ip_str.strip())
        for net in get_configured_trusted_proxies():
            if peer_addr in net:
                return True
    except ValueError:
        return False
    return False


def extract_source_attribution(request: Any, is_synthetic: bool = False) -> SourceAttribution:
    """
    Extracts trustworthy source IP attribution from FastAPI/Starlette request metadata.

    Security Rules:
    1. Inspects the actual underlying socket connection (request.client.host).
    2. If the peer is NOT in BAITSCOPE_TRUSTED_PROXIES / SENTINEL_TRUSTED_PROXIES:
       - Uses the actual peer IP.
       - Discards X-Forwarded-For / X-Real-IP (marking raw string as discarded/unverified).
       - Status: 'verified_peer', Method: 'direct_peer'.
    3. If the peer IS in BAITSCOPE_TRUSTED_PROXIES / SENTINEL_TRUSTED_PROXIES:
       - Traverses X-Forwarded-For chain from right to left to locate first untrusted client IP.
       - If any intermediary hop is malformed or invalid, stops traversal immediately and falls back to peer.
       - Status: 'proxy_attributed', Method: 'trusted_proxy_chain'.
    """
    now = datetime.datetime.now(datetime.UTC)

    # 1. Direct TCP socket peer address
    peer_raw = request.client.host if (request and hasattr(request, "client") and request.client and request.client.host) else "127.0.0.1"
    try:
        peer_ip, peer_ver = normalize_ip_address(peer_raw)
    except ValueError:
        peer_ip, peer_ver = "127.0.0.1", "IPv4"

    headers = getattr(request, "headers", {})
    synth_header = (headers.get("x-baitscope-synthetic") or headers.get("x-sentinel-synthetic")) if hasattr(headers, "get") else None
    if synth_header and str(synth_header).lower() in ("true", "1", "yes"):
        is_synthetic = True

    raw_forwarded = headers.get("x-forwarded-for") if hasattr(headers, "get") else None
    raw_real_ip = headers.get("x-real-ip") if hasattr(headers, "get") else None

    # 2. Peer is NOT a trusted proxy -> Zero Trust: discard all forwarding headers
    if not is_trusted_proxy(peer_ip):
        return SourceAttribution(
            peer_ip=peer_ip,
            client_ip=peer_ip,
            ip_version=peer_ver,
            attribution_method="direct_peer",
            attribution_status="verified_peer",
            is_forwarded=False,
            is_synthetic=is_synthetic,
            observed_at=now,
            raw_forwarded_for=raw_forwarded,
            raw_real_ip=raw_real_ip,
            proxy_hops_count=0
        )

    # 3. Peer IS a trusted proxy -> Process forwarding headers
    if raw_forwarded:
        parts = [p.strip() for p in raw_forwarded.split(",") if p.strip()]
        hops_count = 0
        attributed_cand = None
        
        # Traverse right-to-left
        for candidate in reversed(parts):
            hops_count += 1
            try:
                cand_ip, cand_ver = normalize_ip_address(candidate)
                if not is_trusted_proxy(cand_ip):
                    attributed_cand = (cand_ip, cand_ver)
                    break
            except ValueError:
                # Malformed hop encountered! Traversal must stop immediately.
                # Do NOT trust any hop to the left of a malformed intermediary.
                attributed_cand = None
                break

        if attributed_cand:
            return SourceAttribution(
                peer_ip=peer_ip,
                client_ip=attributed_cand[0],
                ip_version=attributed_cand[1],
                attribution_method="trusted_proxy_chain",
                attribution_status="proxy_attributed",
                is_forwarded=True,
                is_synthetic=is_synthetic,
                observed_at=now,
                raw_forwarded_for=raw_forwarded,
                raw_real_ip=raw_real_ip,
                proxy_hops_count=hops_count
            )

    if raw_real_ip:
        try:
            cand_ip, cand_ver = normalize_ip_address(raw_real_ip)
            return SourceAttribution(
                peer_ip=peer_ip,
                client_ip=cand_ip,
                ip_version=cand_ver,
                attribution_method="trusted_proxy_chain",
                attribution_status="proxy_attributed",
                is_forwarded=True,
                is_synthetic=is_synthetic,
                observed_at=now,
                raw_forwarded_for=raw_forwarded,
                raw_real_ip=raw_real_ip,
                proxy_hops_count=1
            )
        except ValueError:
            pass

    # Fallback to peer when forwarding headers are missing or invalid
    return SourceAttribution(
        peer_ip=peer_ip,
        client_ip=peer_ip,
        ip_version=peer_ver,
        attribution_method="direct_peer",
        attribution_status="verified_peer",
        is_forwarded=False,
        is_synthetic=is_synthetic,
        observed_at=now,
        raw_forwarded_for=raw_forwarded,
        raw_real_ip=raw_real_ip,
        proxy_hops_count=0
    )
