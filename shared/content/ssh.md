# SSH Key Hygiene -- Your Cryptographic Identity

## How SSH Keys Work

SSH (Secure Shell) uses public-key cryptography to authenticate you to remote servers. Instead of typing a password, you prove your identity by demonstrating that you hold a private key corresponding to a public key the server already trusts.

Your SSH key pair consists of two files:

- **Private key** (`~/.ssh/id_ed25519`): This is your secret. It never leaves your machine. Anyone who obtains this file can impersonate you on every server that trusts the corresponding public key.
- **Public key** (`~/.ssh/id_ed25519.pub`): This is shared freely. You place it in `~/.ssh/authorized_keys` on servers you want to access. It cannot be used to derive the private key.

When you connect to a server, your SSH client proves it holds the private key through a cryptographic challenge-response protocol -- the private key is never transmitted over the network.

## Why SSH Keys Matter for Privacy

SSH keys are a critical part of your digital identity:

1. **Server access**: Your keys grant access to servers, cloud infrastructure, code repositories, and CI/CD pipelines.
2. **Identity correlation**: Public keys are globally unique. The same key appearing on GitHub, GitLab, and a corporate server links those identities together.
3. **Forensic trail**: Your `known_hosts` file records every server you have ever connected to -- a detailed log of your infrastructure and travel patterns.

## SSH Key Algorithms: A Brief History

### DSA (Digital Signature Algorithm) -- Broken

DSA was the original SSH key algorithm. It is limited to 1024-bit keys, which are trivially factorable with modern hardware. OpenSSH deprecated DSA support in version 7.0 (2015) and disabled it by default in 8.8 (2021). **If you have a DSA key, replace it immediately.**

### RSA (Rivest-Shamir-Adleman) -- Aging

RSA has been the workhorse of SSH for decades. At 4096 bits, it remains secure against classical computers. However, RSA keys are large, slow to generate, and increasingly vulnerable to advances in quantum computing. NIST currently considers RSA-2048 acceptable but recommends planning for transition. RSA-1024 is dangerously weak and should never be used.

### ECDSA (Elliptic Curve Digital Signature Algorithm) -- Controversial

ECDSA uses NIST P-256/P-384/P-521 curves, which offer smaller keys and faster operations than RSA. However, these curves were designed with input from the NSA, leading some cryptographers to question whether backdoors exist in the curve parameters. ECDSA also requires a high-quality random number generator during signing -- a flawed RNG can leak the private key entirely (as happened with the PlayStation 3 hack). Like RSA, ECDSA is vulnerable to quantum attacks.

### Ed25519 -- Recommended

Ed25519 uses Curve25519, designed by Daniel J. Bernstein with full transparency and no government involvement. It offers:

- **Strong security**: 128-bit security level, equivalent to RSA-3072
- **Small keys**: 256-bit (32-byte) keys vs 4096-bit for strong RSA
- **Fast operations**: Signing and verification are significantly faster than RSA
- **Deterministic signatures**: No dependency on random number quality during signing
- **Side-channel resistance**: Designed to resist timing attacks

Ed25519 is the recommended choice for all new SSH keys.

## Why Passphraseless Keys Are Dangerous

An unencrypted private key is a plaintext file. If your laptop is stolen, your disk is imaged, your backup is compromised, or malware reads your home directory, the attacker has immediate access to every server that trusts that key.

A passphrase encrypts the private key at rest. Even if the file is stolen, it cannot be used without the passphrase. Modern SSH agents (`ssh-agent`, macOS Keychain, GNOME Keyring) cache the decrypted key in memory so you only type the passphrase once per session.

**Best practice**: Always protect private keys with a strong passphrase. Use `ssh-agent` for convenience.

## Agent Forwarding: A Hidden Attack Vector

SSH agent forwarding (`ForwardAgent yes`) allows a remote server to use your local SSH agent to authenticate to other servers. This is convenient for "jump host" workflows but creates a significant security risk.

When agent forwarding is enabled:

1. You connect to Server A with your key.
2. Server A can now use your SSH agent to authenticate as you to Server B, C, D, and any other server.
3. If Server A is compromised, the attacker can silently use your forwarded agent to access all your other servers.

The safer alternative is **ProxyJump** (`ssh -J jumphost targethost`), which tunnels the SSH connection through the jump host without exposing your agent.

## known_hosts: Your Connection Log

Every time you connect to a new SSH server, its host key fingerprint is saved to `~/.ssh/known_hosts`. By default, this file stores hostnames in plaintext. Anyone who reads this file can enumerate:

- Every server you have ever connected to
- IP addresses of your infrastructure
- Hostnames that may reveal internal naming conventions
- Patterns that indicate travel (connecting to servers in different geographic regions)

**Mitigation**: Hash your known_hosts file with `ssh-keygen -H`. This replaces plaintext hostnames with SHA-256 hashes, preventing casual enumeration while still allowing SSH to verify host keys. Enable `HashKnownHosts yes` in your SSH config to hash new entries automatically.

## Post-Quantum Considerations

Quantum computers capable of breaking RSA and ECDSA (using Shor's algorithm) do not yet exist, but the cryptographic community is actively preparing. NIST finalized its first post-quantum cryptography standards in 2024:

- **ML-KEM** (formerly CRYSTALS-Kyber): Key encapsulation mechanism
- **ML-DSA** (formerly CRYSTALS-Dilithium): Digital signatures
- **SLH-DSA** (formerly SPHINCS+): Hash-based signatures

OpenSSH has begun integrating post-quantum key exchange (using a hybrid of X25519 and ML-KEM) since version 9.0. While post-quantum SSH keys are not yet standardized for authentication, the timeline for transition is:

- **Now**: Use Ed25519 for the strongest classical security
- **Near-term (2025-2030)**: Adopt hybrid key exchange as it becomes available
- **Long-term**: Migrate to post-quantum signature schemes when standardized

The "harvest now, decrypt later" threat means that encrypted SSH sessions captured today could be decrypted by future quantum computers. Using post-quantum key exchange protects session confidentiality even against this threat.

## NIST SP 800-57 Key Management Recommendations

NIST Special Publication 800-57 provides guidance on cryptographic key management:

- **Key rotation**: Rotate keys regularly (every 1-2 years for high-value keys)
- **Key separation**: Use different keys for different purposes (work vs personal, production vs development)
- **Key retirement**: Revoke and destroy keys that are no longer needed
- **Minimum key lengths**: RSA >= 2048 bits (3072 recommended), ECDSA >= P-256, Ed25519 (inherently 256-bit)

## Concrete Hardening Steps

1. **Generate an Ed25519 key**:
   ```
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```

2. **Add a passphrase to existing keys**:
   ```
   ssh-keygen -p -f ~/.ssh/id_rsa
   ```

3. **Hash your known_hosts**:
   ```
   ssh-keygen -H
   ```

4. **Secure your SSH config** (`~/.ssh/config`):
   ```
   Host *
       HashKnownHosts yes
       StrictHostKeyChecking ask
       ForwardAgent no
       AddKeysToAgent yes
       IdentitiesOnly yes
   ```

5. **Fix file permissions**:
   ```
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/id_* ~/.ssh/authorized_keys ~/.ssh/config
   chmod 644 ~/.ssh/*.pub
   ```

6. **Remove DSA keys** and replace with Ed25519.

7. **Audit authorized_keys** regularly -- remove keys for people or systems that no longer need access.

8. **Use ProxyJump instead of agent forwarding**:
   ```
   ssh -J jumphost targethost
   ```
   Or in `~/.ssh/config`:
   ```
   Host target
       ProxyJump jumphost
   ```
