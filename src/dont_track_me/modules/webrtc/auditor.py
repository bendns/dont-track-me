"""WebRTC IP leak detection via STUN server queries."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
from typing import Any

from dont_track_me.core.base import AuditResult, Finding, ThreatLevel

# STUN protocol constants (RFC 5389)
STUN_BINDING_REQUEST = 0x0001
STUN_MAGIC_COOKIE = 0x2112A442
STUN_HEADER_SIZE = 20

# STUN attribute types
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020

# Public STUN servers used to discover externally-visible IP addresses
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun1.l.google.com", 19302),
]

STUN_TIMEOUT = 3  # seconds per query


def _build_stun_request(transaction_id: bytes | None = None) -> tuple[bytes, bytes]:
    """Build a STUN Binding Request packet.

    Returns (packet, transaction_id).
    """
    if transaction_id is None:
        transaction_id = os.urandom(12)

    # Header: type (2) + length (2) + magic cookie (4) + transaction ID (12)
    header = struct.pack(
        "!HHI",
        STUN_BINDING_REQUEST,
        0,  # message length (no attributes)
        STUN_MAGIC_COOKIE,
    )
    return header + transaction_id, transaction_id


def _parse_xor_mapped_address(data: bytes) -> str | None:
    """Parse XOR-MAPPED-ADDRESS attribute value into an IP string."""
    if len(data) < 8:
        return None

    family = data[1]
    if family != 0x01:  # IPv4 only for now
        return None

    xor_ip_bytes = data[4:8]

    # XOR the IP with the magic cookie
    magic_bytes = struct.pack("!I", STUN_MAGIC_COOKIE)
    ip_bytes = bytes(a ^ b for a, b in zip(xor_ip_bytes, magic_bytes, strict=True))

    return str(ipaddress.IPv4Address(ip_bytes))


def _parse_mapped_address(data: bytes) -> str | None:
    """Parse MAPPED-ADDRESS attribute value into an IP string."""
    if len(data) < 8:
        return None

    family = data[1]
    if family != 0x01:  # IPv4 only
        return None

    ip_bytes = data[4:8]
    return str(ipaddress.IPv4Address(ip_bytes))


def _parse_stun_response(response: bytes, transaction_id: bytes) -> str | None:
    """Parse a STUN Binding Response and extract the mapped IP address.

    Prefers XOR-MAPPED-ADDRESS over MAPPED-ADDRESS.
    """
    if len(response) < STUN_HEADER_SIZE:
        return None

    # Verify it's a binding success response (0x0101)
    msg_type, msg_length, magic = struct.unpack("!HHI", response[:8])
    if msg_type != 0x0101 or magic != STUN_MAGIC_COOKIE:
        return None

    # Verify transaction ID matches
    resp_tid = response[8:20]
    if resp_tid != transaction_id:
        return None

    # Parse attributes
    mapped_ip = None
    offset = STUN_HEADER_SIZE
    end = STUN_HEADER_SIZE + msg_length

    while offset + 4 <= end:
        attr_type, attr_length = struct.unpack("!HH", response[offset : offset + 4])
        attr_data = response[offset + 4 : offset + 4 + attr_length]

        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            xor_ip = _parse_xor_mapped_address(attr_data)
            if xor_ip:
                return xor_ip  # prefer XOR-MAPPED-ADDRESS

        if attr_type == ATTR_MAPPED_ADDRESS and mapped_ip is None:
            mapped_ip = _parse_mapped_address(attr_data)

        # Attributes are padded to 4-byte boundaries
        offset += 4 + attr_length
        if attr_length % 4:
            offset += 4 - (attr_length % 4)

    return mapped_ip


def _query_stun_server(server: str, port: int) -> str | None:
    """Send a STUN Binding Request and return the mapped IP address."""
    packet, transaction_id = _build_stun_request()

    try:
        # Resolve hostname first
        addr_info = socket.getaddrinfo(server, port, socket.AF_INET, socket.SOCK_DGRAM)
        if not addr_info:
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(STUN_TIMEOUT)
            sock.sendto(packet, (addr_info[0][4][0], port))
            response, _ = sock.recvfrom(1024)
            return _parse_stun_response(response, transaction_id)
        finally:
            sock.close()
    except (OSError, TimeoutError):
        return None


def _get_local_ips() -> list[str]:
    """Get local IP addresses of this machine."""
    ips: list[str] = []
    try:
        for _family, _type, _proto, _canonname, sockaddr in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET
        ):
            ip = str(sockaddr[0])
            if ip not in ips and ip != "127.0.0.1":
                ips.append(ip)
    except OSError:
        pass
    return ips


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


async def audit_webrtc(**kwargs: Any) -> AuditResult:
    """Audit WebRTC IP leak exposure via STUN server queries."""
    findings: list[Finding] = []
    score = 100
    loop = asyncio.get_event_loop()

    # Query STUN servers concurrently
    stun_tasks = [
        loop.run_in_executor(None, _query_stun_server, server, port)
        for server, port in STUN_SERVERS
    ]
    stun_results = await asyncio.gather(*stun_tasks)

    # Collect unique IPs returned by STUN servers
    stun_ips: list[str] = []
    for ip in stun_results:
        if ip and ip not in stun_ips:
            stun_ips.append(ip)

    local_ips = _get_local_ips()

    if not stun_ips:
        # All STUN queries failed — likely blocked by firewall
        findings.append(
            Finding(
                title="STUN servers unreachable",
                description=(
                    "Could not reach any STUN servers. This likely means WebRTC "
                    "UDP traffic is blocked by your firewall or network configuration, "
                    "which prevents WebRTC IP leaks."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="No action needed — blocked STUN traffic is good for privacy.",
            )
        )
        return AuditResult(
            module_name="webrtc",
            score=90,
            findings=findings,
            raw_data={"stun_ips": [], "local_ips": local_ips},
        )

    # Analyze discovered IPs
    public_ips = [ip for ip in stun_ips if not _is_private_ip(ip)]
    private_ips = [ip for ip in stun_ips if _is_private_ip(ip)]

    if public_ips:
        findings.append(
            Finding(
                title=f"Public IP exposed via WebRTC: {', '.join(public_ips)}",
                description=(
                    "STUN servers revealed your public IP address. In a browser with "
                    "WebRTC enabled, any website can discover this IP — even if you're "
                    "using a VPN. This completely bypasses VPN protection."
                ),
                threat_level=ThreatLevel.HIGH,
                remediation=(
                    "Disable WebRTC in your browser: "
                    "Firefox: about:config → media.peerconnection.enabled = false. "
                    "Chrome: install 'WebRTC Leak Prevent' extension. "
                    "Brave: Settings → Privacy → WebRTC IP Handling Policy → "
                    "'Disable non-proxied UDP'."
                ),
            )
        )
        score -= 40

    if private_ips:
        findings.append(
            Finding(
                title=f"Local IP exposed via WebRTC: {', '.join(private_ips)}",
                description=(
                    "STUN servers returned a private/local IP address. While not as "
                    "severe as a public IP leak, this reveals your local network "
                    "topology and can be used for fingerprinting."
                ),
                threat_level=ThreatLevel.MEDIUM,
                remediation=(
                    "Disable WebRTC or restrict it to prevent local IP enumeration. "
                    "In Firefox: set media.peerconnection.enabled to false."
                ),
            )
        )
        score -= 20

    if len(stun_ips) > 1:
        findings.append(
            Finding(
                title=f"Multiple IPs detected: {', '.join(stun_ips)}",
                description=(
                    "Different STUN servers returned different IP addresses. "
                    "This may indicate split tunneling, multiple network interfaces, "
                    "or an inconsistent VPN configuration."
                ),
                threat_level=ThreatLevel.INFO,
                remediation="Review your VPN and network configuration for consistency.",
            )
        )

    if not public_ips and not private_ips:
        findings.append(
            Finding(
                title="WebRTC IP leak check passed",
                description="STUN servers did not reveal any concerning IP addresses.",
                threat_level=ThreatLevel.INFO,
                remediation="Consider disabling WebRTC entirely for maximum privacy.",
            )
        )

    score = max(0, min(100, score))

    return AuditResult(
        module_name="webrtc",
        score=score,
        findings=findings,
        raw_data={
            "stun_ips": stun_ips,
            "local_ips": local_ips,
            "public_ips": public_ips,
            "private_ips": private_ips,
        },
    )
