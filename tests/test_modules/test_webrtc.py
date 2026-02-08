"""Tests for the WebRTC module."""

import ipaddress
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from dont_track_me.modules.webrtc.auditor import (
    STUN_MAGIC_COOKIE,
    _build_stun_request,
    _get_local_ips,
    _is_private_ip,
    _parse_mapped_address,
    _parse_stun_response,
    _parse_xor_mapped_address,
    audit_webrtc,
)
from dont_track_me.modules.webrtc.protector import protect_webrtc

# --- STUN packet construction ---


def test_build_stun_request_structure():
    """Request should be exactly 20 bytes with correct header."""
    packet, tid = _build_stun_request()
    assert len(packet) == 20
    assert len(tid) == 12

    msg_type, msg_length, magic = struct.unpack("!HHI", packet[:8])
    assert msg_type == 0x0001  # Binding Request
    assert msg_length == 0  # no attributes
    assert magic == STUN_MAGIC_COOKIE


def test_build_stun_request_with_fixed_tid():
    """Should use provided transaction ID."""
    tid = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    packet, returned_tid = _build_stun_request(transaction_id=tid)
    assert returned_tid == tid
    assert packet[8:20] == tid


def test_build_stun_request_random_tid():
    """Two requests should have different transaction IDs."""
    _, tid1 = _build_stun_request()
    _, tid2 = _build_stun_request()
    assert tid1 != tid2


# --- STUN response parsing ---


def _make_stun_response(transaction_id: bytes, ip: str, use_xor: bool = True) -> bytes:
    """Build a fake STUN Binding Response with a mapped address attribute."""
    ip_obj = ipaddress.IPv4Address(ip)

    if use_xor:
        # XOR-MAPPED-ADDRESS (0x0020)
        attr_type = 0x0020
        magic_bytes = struct.pack("!I", STUN_MAGIC_COOKIE)
        xor_ip = bytes(a ^ b for a, b in zip(ip_obj.packed, magic_bytes, strict=True))
        xor_port = 0x0000 ^ (STUN_MAGIC_COOKIE >> 16)  # port 0 XORed
        attr_value = struct.pack("!BBH", 0x00, 0x01, xor_port) + xor_ip
    else:
        # MAPPED-ADDRESS (0x0001)
        attr_type = 0x0001
        attr_value = struct.pack("!BBH", 0x00, 0x01, 0x0000) + ip_obj.packed

    attr_header = struct.pack("!HH", attr_type, len(attr_value))
    attributes = attr_header + attr_value

    # Response header: type=0x0101 (Binding Success), length, magic, tid
    header = struct.pack("!HHI", 0x0101, len(attributes), STUN_MAGIC_COOKIE)
    return header + transaction_id + attributes


def test_parse_xor_mapped_address():
    """Should correctly XOR-decode an IPv4 address."""
    # Encode 8.8.4.4 XORed with magic cookie
    ip = "8.8.4.4"
    ip_bytes = ipaddress.IPv4Address(ip).packed
    magic_bytes = struct.pack("!I", STUN_MAGIC_COOKIE)
    xor_ip = bytes(a ^ b for a, b in zip(ip_bytes, magic_bytes, strict=True))
    xor_port = 0x1234 ^ (STUN_MAGIC_COOKIE >> 16)

    data = struct.pack("!BBH", 0x00, 0x01, xor_port) + xor_ip
    result = _parse_xor_mapped_address(data)
    assert result == ip


def test_parse_mapped_address():
    """Should correctly decode a plain IPv4 address."""
    ip = "192.168.1.100"
    ip_bytes = ipaddress.IPv4Address(ip).packed
    data = struct.pack("!BBH", 0x00, 0x01, 0x1234) + ip_bytes
    result = _parse_mapped_address(data)
    assert result == ip


def test_parse_stun_response_xor():
    """Should extract IP from XOR-MAPPED-ADDRESS response."""
    tid = b"\x01" * 12
    response = _make_stun_response(tid, "9.9.9.9", use_xor=True)
    result = _parse_stun_response(response, tid)
    assert result == "9.9.9.9"


def test_parse_stun_response_plain():
    """Should extract IP from MAPPED-ADDRESS response."""
    tid = b"\x02" * 12
    response = _make_stun_response(tid, "10.0.0.5", use_xor=False)
    result = _parse_stun_response(response, tid)
    assert result == "10.0.0.5"


def test_parse_stun_response_wrong_tid():
    """Should reject response with mismatched transaction ID."""
    tid = b"\x01" * 12
    wrong_tid = b"\x02" * 12
    response = _make_stun_response(tid, "9.9.9.9")
    result = _parse_stun_response(response, wrong_tid)
    assert result is None


def test_parse_stun_response_too_short():
    """Should return None for truncated response."""
    assert _parse_stun_response(b"\x00" * 10, b"\x00" * 12) is None


def test_parse_xor_mapped_address_too_short():
    """Should return None for truncated attribute data."""
    assert _parse_xor_mapped_address(b"\x00\x01") is None


def test_parse_mapped_address_too_short():
    """Should return None for truncated attribute data."""
    assert _parse_mapped_address(b"\x00\x01") is None


def test_parse_xor_mapped_address_ipv6_skipped():
    """Should return None for IPv6 family (0x02)."""
    data = struct.pack("!BBH", 0x00, 0x02, 0x0000) + b"\x00" * 16
    assert _parse_xor_mapped_address(data) is None


# --- Helper functions ---


def test_is_private_ip():
    """Should identify private vs public IPs."""
    assert _is_private_ip("192.168.1.1") is True
    assert _is_private_ip("10.0.0.1") is True
    assert _is_private_ip("172.16.0.1") is True
    assert _is_private_ip("8.8.8.8") is False
    assert _is_private_ip("1.1.1.1") is False


def test_is_private_ip_invalid():
    """Should return False for invalid input."""
    assert _is_private_ip("not-an-ip") is False


def test_get_local_ips():
    """Should return a list of strings (may be empty in CI)."""
    ips = _get_local_ips()
    assert isinstance(ips, list)
    for ip in ips:
        assert isinstance(ip, str)
    # 127.0.0.1 should be excluded
    assert "127.0.0.1" not in ips


# --- Audit function (mocked network) ---


@pytest.mark.asyncio
async def test_audit_webrtc_public_ip_leak():
    """Should detect public IP exposure when STUN returns a public IP."""
    tid = b"\xaa" * 12
    response = _make_stun_response(tid, "8.8.8.8", use_xor=True)

    mock_socket = MagicMock()
    mock_socket.recvfrom.return_value = (response, ("stun.example.com", 19302))

    with (
        patch("dont_track_me.modules.webrtc.auditor._build_stun_request") as mock_build,
        patch("dont_track_me.modules.webrtc.auditor.socket.socket", return_value=mock_socket),
        patch("dont_track_me.modules.webrtc.auditor.socket.getaddrinfo") as mock_getaddr,
        patch("dont_track_me.modules.webrtc.auditor._get_local_ips", return_value=["192.168.1.5"]),
    ):
        mock_build.return_value = (b"\x00" * 20, tid)
        mock_getaddr.return_value = [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("1.2.3.4", 0))]

        result = await audit_webrtc()

    assert result.module_name == "webrtc"
    assert result.score < 100
    assert any("Public IP exposed" in f.title for f in result.findings)
    assert "8.8.8.8" in result.raw_data["public_ips"]


@pytest.mark.asyncio
async def test_audit_webrtc_private_ip_leak():
    """Should detect local IP exposure when STUN returns a private IP."""
    tid = b"\xbb" * 12
    response = _make_stun_response(tid, "192.168.1.100", use_xor=True)

    mock_socket = MagicMock()
    mock_socket.recvfrom.return_value = (response, ("stun.example.com", 19302))

    with (
        patch("dont_track_me.modules.webrtc.auditor._build_stun_request") as mock_build,
        patch("dont_track_me.modules.webrtc.auditor.socket.socket", return_value=mock_socket),
        patch("dont_track_me.modules.webrtc.auditor.socket.getaddrinfo") as mock_getaddr,
        patch("dont_track_me.modules.webrtc.auditor._get_local_ips", return_value=["192.168.1.5"]),
    ):
        mock_build.return_value = (b"\x00" * 20, tid)
        mock_getaddr.return_value = [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("1.2.3.4", 0))]

        result = await audit_webrtc()

    assert result.module_name == "webrtc"
    assert result.score < 100
    assert any("Local IP exposed" in f.title for f in result.findings)
    assert "192.168.1.100" in result.raw_data["private_ips"]


@pytest.mark.asyncio
async def test_audit_webrtc_stun_blocked():
    """Should report good score when STUN is unreachable."""
    mock_socket = MagicMock()
    mock_socket.recvfrom.side_effect = TimeoutError("timed out")

    with (
        patch("dont_track_me.modules.webrtc.auditor.socket.socket", return_value=mock_socket),
        patch("dont_track_me.modules.webrtc.auditor.socket.getaddrinfo") as mock_getaddr,
        patch("dont_track_me.modules.webrtc.auditor._get_local_ips", return_value=[]),
    ):
        mock_getaddr.return_value = [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("1.2.3.4", 0))]

        result = await audit_webrtc()

    assert result.module_name == "webrtc"
    assert result.score == 90
    assert any("unreachable" in f.title for f in result.findings)


# --- Protector ---


@pytest.mark.asyncio
async def test_protect_webrtc_returns_recommendations():
    """Should return browser-specific recommendations."""
    result = await protect_webrtc()
    assert result.module_name == "webrtc"
    assert result.dry_run is True
    assert len(result.actions_taken) == 0
    assert len(result.actions_available) >= 5  # 5 browsers + general

    # Verify key browsers are covered
    all_actions = " ".join(result.actions_available)
    assert "Firefox" in all_actions
    assert "Chrome" in all_actions
    assert "Brave" in all_actions
    assert "Safari" in all_actions
    assert "Tor" in all_actions


@pytest.mark.asyncio
async def test_protect_webrtc_dry_run_false():
    """Protector should still not take actions even with dry_run=False."""
    result = await protect_webrtc(dry_run=False)
    assert result.dry_run is False
    assert len(result.actions_taken) == 0  # can't modify browser settings
    assert len(result.actions_available) >= 5
