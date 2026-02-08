"""Tests for the certificates module."""

from __future__ import annotations

import ssl as _real_ssl
from unittest.mock import MagicMock, patch

import pytest

from dont_track_me.modules.certificates.auditor import (
    SUSPICIOUS_CAS,
    audit_certificates,
)
from dont_track_me.modules.certificates.module import CertificatesModule
from dont_track_me.modules.certificates.protector import protect_certificates


def _make_cert(
    org: str = "Test Org",
    cn: str = "Test CA",
    not_after: str = "Dec 31 23:59:59 2099 GMT",
    not_before: str = "Jan  1 00:00:00 2020 GMT",
    serial: str = "AABBCCDD",
) -> dict:
    """Create a fake certificate dict matching ssl.get_ca_certs() format."""
    return {
        "subject": (
            (("organizationName", org),),
            (("commonName", cn),),
        ),
        "issuer": (
            (("organizationName", org),),
            (("commonName", cn),),
        ),
        "notBefore": not_before,
        "notAfter": not_after,
        "serialNumber": serial,
    }


def _mock_ssl_context(certs: list[dict] | None = None):
    """Create a mock ssl.create_default_context() that returns the given certs."""
    if certs is None:
        certs = [_make_cert()]
    mock_ctx = MagicMock()
    mock_ctx.get_ca_certs.return_value = certs
    mock_ctx.minimum_version = 3  # TLS 1.2
    return mock_ctx


@pytest.mark.asyncio
async def test_audit_returns_result():
    """Audit runs and returns AuditResult with module_name='certificates'."""
    certs = [_make_cert() for _ in range(5)]
    mock_ctx = _mock_ssl_context(certs)

    with patch("dont_track_me.modules.certificates.auditor.ssl") as mock_ssl:
        mock_ssl.create_default_context.return_value = mock_ctx
        mock_ssl.SSLError = Exception
        mock_ssl.PROTOCOL_TLS_CLIENT = 2
        mock_ssl.cert_time_to_seconds = _real_ssl.cert_time_to_seconds
        # Ensure TLS version check doesn't fail
        tls_ctx = MagicMock()
        tls_ctx.minimum_version = 3  # TLS 1.2
        mock_ssl.SSLContext.return_value = tls_ctx
        mock_ssl.TLSVersion.TLSv1 = 1
        mock_ssl.TLSVersion.TLSv1_1 = 2

        result = await audit_certificates()

    assert result.module_name == "certificates"
    assert isinstance(result.findings, list)
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_audit_score_range():
    """Audit score is always between 0 and 100 inclusive."""
    certs = [_make_cert() for _ in range(5)]
    mock_ctx = _mock_ssl_context(certs)

    with patch("dont_track_me.modules.certificates.auditor.ssl") as mock_ssl:
        mock_ssl.create_default_context.return_value = mock_ctx
        mock_ssl.SSLError = Exception
        mock_ssl.PROTOCOL_TLS_CLIENT = 2
        mock_ssl.cert_time_to_seconds = _real_ssl.cert_time_to_seconds
        tls_ctx = MagicMock()
        tls_ctx.minimum_version = 3
        mock_ssl.SSLContext.return_value = tls_ctx
        mock_ssl.TLSVersion.TLSv1 = 1
        mock_ssl.TLSVersion.TLSv1_1 = 2

        result = await audit_certificates()

    assert 0 <= result.score <= 100


@pytest.mark.asyncio
async def test_protect_dry_run():
    """Protect with dry_run=True returns ProtectionResult with dry_run=True."""
    mock_ctx = _mock_ssl_context([_make_cert()])

    with patch("dont_track_me.modules.certificates.protector.ssl") as mock_ssl:
        mock_ssl.create_default_context.return_value = mock_ctx
        mock_ssl.SSLError = Exception

        result = await protect_certificates(dry_run=True)

    assert result.module_name == "certificates"
    assert result.dry_run is True
    assert len(result.actions_taken) == 0


def test_module_attributes():
    """Module has correct name, display_name, and description."""
    mod = CertificatesModule()
    assert mod.name == "certificates"
    assert mod.display_name == "TLS Certificate Trust Audit"
    assert "certificate" in mod.description.lower() or "CA" in mod.description


def test_module_educational_content():
    """Educational content mentions certificates or TLS and is substantial."""
    mod = CertificatesModule()
    content = mod.get_educational_content()
    lower_content = content.lower()
    assert "certificate" in lower_content or "tls" in lower_content
    assert len(content) > 500


def test_suspicious_ca_list():
    """SUSPICIOUS_CAS list is non-empty and contains known bad actors."""
    assert len(SUSPICIOUS_CAS) > 0
    assert "CNNIC" in SUSPICIOUS_CAS
    assert "WoSign" in SUSPICIOUS_CAS
    assert "DarkMatter" in SUSPICIOUS_CAS
    assert "TurkTrust" in SUSPICIOUS_CAS


@pytest.mark.asyncio
async def test_cert_parsing():
    """Mock ssl context with known certs and verify parsing works."""
    certs = [
        _make_cert(org="Mozilla Corp", cn="Mozilla Root CA"),
        _make_cert(org="Let's Encrypt", cn="ISRG Root X1"),
    ]
    mock_ctx = _mock_ssl_context(certs)

    with patch("dont_track_me.modules.certificates.auditor.ssl") as mock_ssl:
        mock_ssl.create_default_context.return_value = mock_ctx
        mock_ssl.SSLError = Exception
        mock_ssl.PROTOCOL_TLS_CLIENT = 2
        mock_ssl.cert_time_to_seconds = _real_ssl.cert_time_to_seconds
        tls_ctx = MagicMock()
        tls_ctx.minimum_version = 3
        mock_ssl.SSLContext.return_value = tls_ctx
        mock_ssl.TLSVersion.TLSv1 = 1
        mock_ssl.TLSVersion.TLSv1_1 = 2

        result = await audit_certificates()

    assert result.module_name == "certificates"
    assert result.raw_data["total_ca_count"] == 2
    assert len(result.raw_data["expired_certs"]) == 0
    assert len(result.raw_data["suspicious_cas"]) == 0


@pytest.mark.asyncio
async def test_expired_cert_detection():
    """A cert with notAfter in the past is flagged as expired."""
    certs = [
        _make_cert(org="Old CA", cn="Expired Root", not_after="Jan  1 00:00:00 2010 GMT"),
        _make_cert(org="Good CA", cn="Valid Root", not_after="Dec 31 23:59:59 2099 GMT"),
    ]
    mock_ctx = _mock_ssl_context(certs)

    with patch("dont_track_me.modules.certificates.auditor.ssl") as mock_ssl:
        mock_ssl.create_default_context.return_value = mock_ctx
        mock_ssl.SSLError = Exception
        mock_ssl.PROTOCOL_TLS_CLIENT = 2
        mock_ssl.cert_time_to_seconds = _real_ssl.cert_time_to_seconds
        tls_ctx = MagicMock()
        tls_ctx.minimum_version = 3
        mock_ssl.SSLContext.return_value = tls_ctx
        mock_ssl.TLSVersion.TLSv1 = 1
        mock_ssl.TLSVersion.TLSv1_1 = 2

        result = await audit_certificates()

    assert len(result.raw_data["expired_certs"]) == 1
    assert "Old CA" in result.raw_data["expired_certs"][0]
    # Score should be less than 100 due to expired cert
    assert result.score < 100


@pytest.mark.asyncio
async def test_protect_has_recommendations():
    """Protect returns actions_available with at least 1 entry."""
    mock_ctx = _mock_ssl_context([_make_cert()])

    with patch("dont_track_me.modules.certificates.protector.ssl") as mock_ssl:
        mock_ssl.create_default_context.return_value = mock_ctx
        mock_ssl.SSLError = Exception

        result = await protect_certificates(dry_run=True)

    assert len(result.actions_available) >= 1


@pytest.mark.asyncio
async def test_suspicious_ca_detection():
    """A cert from a known suspicious CA is flagged."""
    certs = [
        _make_cert(org="CNNIC", cn="China Internet Network Information Center Root"),
        _make_cert(org="Good CA", cn="Trustworthy Root"),
    ]
    mock_ctx = _mock_ssl_context(certs)

    with patch("dont_track_me.modules.certificates.auditor.ssl") as mock_ssl:
        mock_ssl.create_default_context.return_value = mock_ctx
        mock_ssl.SSLError = Exception
        mock_ssl.PROTOCOL_TLS_CLIENT = 2
        mock_ssl.cert_time_to_seconds = _real_ssl.cert_time_to_seconds
        tls_ctx = MagicMock()
        tls_ctx.minimum_version = 3
        mock_ssl.SSLContext.return_value = tls_ctx
        mock_ssl.TLSVersion.TLSv1 = 1
        mock_ssl.TLSVersion.TLSv1_1 = 2

        result = await audit_certificates()

    assert "CNNIC" in result.raw_data["suspicious_cas"]
    assert result.score < 100
    # Find the suspicious CA finding
    suspicious_findings = [f for f in result.findings if "suspicious" in f.title.lower()]
    assert len(suspicious_findings) >= 1
