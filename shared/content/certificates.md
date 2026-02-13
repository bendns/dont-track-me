# TLS Certificates -- The Foundation of Internet Trust (and Its Cracks)

## What Are Certificate Authorities?

Every time you see the padlock icon in your browser, you are relying on a system of trust built on Certificate Authorities (CAs). A CA is an organization trusted by your operating system and browser to vouch for the identity of websites. When you connect to `https://yourbank.com`, the bank presents a certificate signed by a CA. Your browser checks: "Do I trust this CA?" If yes, the connection proceeds. If not, you get a scary warning page.

Your system ships with a **trust store** -- a list of 100-200+ root CA certificates that are implicitly trusted. Every single one of those CAs has the power to issue a valid certificate for **any domain on the internet**. This is the fundamental weakness of the CA trust model.

## The CA Trust Model's Fatal Flaw

The current PKI (Public Key Infrastructure) operates on a model where **any trusted CA can issue certificates for any domain**. Your system might trust 150 different CAs from dozens of countries. Each one can create a perfectly valid certificate for `google.com`, `yourbank.com`, or any other site. You only need one compromised or malicious CA to undermine the entire system.

This is not a theoretical concern. It has happened repeatedly.

## Historical CA Compromises

### DigiNotar (2011) -- The Breach That Changed Everything

In 2011, hackers breached DigiNotar, a Dutch CA, and issued fraudulent certificates for over 500 domains including `*.google.com`. These fake certificates were used to intercept Gmail communications of Iranian citizens -- likely by the Iranian government. The attack went undetected for weeks. DigiNotar was subsequently distrusted by all browsers and went bankrupt.

This single incident demonstrated that a CA compromise is not just a technical problem -- it is a human rights issue. People relying on HTTPS for secure communication were silently surveilled.

### CNNIC and WoSign (2015-2016)

The China Internet Network Information Center (CNNIC) issued an intermediate CA certificate to an organization that used it to issue unauthorized certificates for Google domains. Google discovered this through Certificate Transparency logs and moved to distrust CNNIC.

WoSign, another Chinese CA, was found to have issued fraudulent certificates (including for GitHub), backdated SHA-1 certificates to circumvent browser deadlines, and secretly acquired StartCom (an Israeli CA) while concealing the acquisition. Mozilla, Google, and Apple all distrusted WoSign and StartCom certificates.

### TurkTrust (2012)

Turkish CA TurkTrust accidentally issued intermediate CA certificates to two organizations instead of regular end-entity certificates. One of these was used to create a fraudulent certificate for `*.google.com`. The certificate was used for MITM interception of Google traffic in Turkey.

### Comodo Breach (2011)

An attacker compromised a Comodo registration authority and issued fraudulent certificates for major domains including `login.yahoo.com`, `mail.google.com`, `login.skype.com`, and `addons.mozilla.org`. The attacker was traced to Iran and the certificates appeared designed for surveillance.

## State-Sponsored CA Abuse

Government-controlled CAs represent a unique threat because they combine the technical capability to issue certificates with the political motivation to surveil citizens.

**ANSSI (France)**: The French government's cybersecurity agency operated a CA that was found to have issued unauthorized certificates for Google domains in 2013. This was used within a French government network, ostensibly for network inspection, but demonstrated the surveillance capability of government CAs.

**Trustwave (United States)**: Trustwave, a US-based CA, admitted to issuing a subordinate CA certificate to a private company for the explicit purpose of performing Deep Packet Inspection (DPI) -- essentially man-in-the-middle attacks on encrypted traffic. This meant the company could silently intercept and inspect all HTTPS traffic passing through its network.

**DarkMatter (UAE)**: DarkMatter, a UAE-based cybersecurity firm, applied to become a trusted root CA in Firefox despite being linked to "Project Raven," a surveillance operation that targeted journalists, activists, and foreign governments. Mozilla ultimately rejected their application after Reuters exposed their surveillance activities.

These cases illustrate a fundamental tension: governments want the ability to inspect encrypted traffic (for law enforcement, national security, or censorship), and the CA system gives them a technical mechanism to do so silently.

## Certificate Transparency -- The Defense

Certificate Transparency (CT) was developed by Google engineers in direct response to the DigiNotar breach. CT requires CAs to publicly log every certificate they issue in append-only, cryptographically verifiable logs.

How it works:
1. A CA issues a certificate and submits it to one or more CT logs
2. The CT log returns a Signed Certificate Timestamp (SCT)
3. The certificate includes the SCT, proving it was logged
4. Anyone can monitor CT logs to detect unauthorized certificates

Chrome requires CT compliance for all publicly trusted certificates since April 2018. Safari followed with similar requirements. This means a CA cannot silently issue a fraudulent certificate -- it would either appear in the public logs (and be detected) or lack the required SCTs (and be rejected by browsers).

You can search CT logs yourself at [crt.sh](https://crt.sh) to see every certificate ever issued for a domain.

## Why Expired CAs in Your Trust Store Are Dangerous

When a CA certificate expires, it should be removed from your trust store. Keeping expired CAs is problematic for several reasons:

- **Stale trust store**: An outdated trust store may still trust CAs that have been compromised or distrusted by browsers, leaving you vulnerable to attacks that browsers have already mitigated.
- **Inconsistent security**: Your browser may distrust a CA, but other applications (curl, wget, Python, Node.js) use the system trust store directly and may still accept certificates from distrusted CAs.
- **Attack surface**: Every CA in your trust store is an entity that could potentially be compromised. Minimizing the store reduces risk.

## TLS Version History -- Why 1.0 and 1.1 Must Be Disabled

- **SSL 2.0 (1995)**: Fundamentally broken, never use.
- **SSL 3.0 (1996)**: Broken by POODLE attack (2014), disabled everywhere.
- **TLS 1.0 (1999)**: Vulnerable to BEAST attack. Deprecated by RFC 8996 (2021). All major browsers disabled support in 2020.
- **TLS 1.1 (2006)**: No known critical vulnerabilities but lacks AEAD ciphers and modern security features. Deprecated alongside TLS 1.0 by RFC 8996.
- **TLS 1.2 (2008)**: Current minimum recommended version. Supports AEAD ciphers (AES-GCM, ChaCha20-Poly1305) but handshake is not encrypted.
- **TLS 1.3 (2018)**: Current best practice. Encrypted handshake, mandatory forward secrecy, removed legacy cipher suites, faster connection setup (1-RTT, 0-RTT).

If your system still allows TLS 1.0 or 1.1, applications may negotiate these weak versions when connecting to misconfigured servers, exposing you to known protocol-level attacks.

## Post-Quantum Implications

The certificates and TLS protocols that protect the internet today rely on mathematical problems (RSA, elliptic curves) that quantum computers could theoretically solve. NIST has finalized three post-quantum cryptographic standards:

- **FIPS 203 (ML-KEM)**: Key encapsulation based on lattice problems, replacing RSA/ECDH key exchange
- **FIPS 204 (ML-DSA)**: Digital signatures based on lattice problems, replacing RSA/ECDSA signatures
- **FIPS 205 (SLH-DSA)**: Hash-based digital signatures as a conservative alternative

Chrome and other browsers have begun experimenting with hybrid key exchange (combining classical and post-quantum algorithms). The transition will take years, but certificates issued today with classical algorithms face a "harvest now, decrypt later" threat -- adversaries can record encrypted traffic now and decrypt it once quantum computers are available.

## Concrete Steps to Harden Your Trust Store

1. **Audit your trust store**: Run this module to identify suspicious, expired, or weak CAs.
2. **Remove distrusted CAs**: Follow the platform-specific instructions provided by this tool to distrust or remove CAs that have been involved in security incidents.
3. **Disable TLS 1.0/1.1**: Ensure your browsers and system are configured to require TLS 1.2 at minimum, with TLS 1.3 preferred.
4. **Monitor Certificate Transparency**: If you own domains, set up monitoring at crt.sh or use a CT monitoring service to detect unauthorized certificate issuance.
5. **Keep your system updated**: OS and browser updates include trust store changes that remove compromised CAs. Delaying updates leaves you trusting CAs that the security community has already distrusted.
6. **Use HTTPS Everywhere**: Ensure your browser enforces HTTPS connections. Firefox's HTTPS-Only Mode and Chrome's HTTPS-First Mode redirect HTTP requests to HTTPS automatically.
7. **Consider certificate pinning**: For high-security applications, HTTP Public Key Pinning (HPKP) or its successor, Certificate Authority Authorization (CAA) DNS records, can limit which CAs are allowed to issue certificates for your domains.
