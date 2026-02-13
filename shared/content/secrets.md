# Local Secrets Exposure — Your Credentials Are Probably Leaking

## The Scale of the Problem

Secrets leaking into public repositories is one of the most pervasive security issues in software development. According to GitGuardian's annual reports, **12.8 million secrets were leaked on GitHub in 2023**, and that number surged to **39 million in 2024**. These are not hypothetical risks — they are real API keys, database passwords, cloud credentials, and private tokens that attackers actively scan for and exploit within minutes of exposure.

But public repositories are only part of the story. The secrets sitting on your local machine — in dotfiles, shell history, configuration files, and project directories — are equally vulnerable. A stolen laptop, a misconfigured backup, or a single `git push` to the wrong remote can expose them all.

## How Secrets Leak

### Git Commits

The most common vector. A developer adds a `.env` file or hardcodes an API key during development and commits it. Even if the file is later removed, the secret remains in git history forever. Running `git log --all --full-history -- .env` on many repositories reveals credentials that were "deleted" months ago.

### Shell History

Every command you type is recorded. When you run `export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...` or `curl -H "Authorization: Bearer sk-..."`, that secret is written to `~/.bash_history` or `~/.zsh_history` in plain text. These files persist across reboots and are readable by any process running as your user.

### Dotfiles and Configuration Files

Files like `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json`, and `~/.netrc` often contain authentication tokens stored in plain text. Developers who sync their dotfiles to GitHub (a common practice) frequently expose these credentials. The `~/.aws/credentials` file is particularly dangerous — it provides direct access to cloud infrastructure that can cost thousands of dollars if misused.

### Environment Variable Files

`.env` files were designed to keep secrets out of code, but they introduce their own risks. They are frequently committed to repositories by accident (especially when `.gitignore` is not properly configured). They appear in Docker image layers when copied during builds. They are often shared between team members via insecure channels like Slack or email.

### Backups and Cloud Sync

Time Machine, Dropbox, Google Drive, and other sync services may upload your entire home directory — including plaintext credentials — to cloud storage. This creates copies of your secrets that you may not even be aware of.

## Why .env Files Are Not Secure

The `.env` file pattern gives a false sense of security. Yes, it separates secrets from code, but the secrets are still stored in plain text on disk. Common problems include:

- **Accidental commits**: Without a `.gitignore` entry, `git add .` captures everything
- **Docker layer exposure**: `COPY . .` in a Dockerfile copies `.env` into the image layer, which is visible to anyone who pulls the image
- **Shared development**: `.env` files are often passed around via chat or email, creating uncontrolled copies
- **No access control**: any process running as your user can read `.env` files
- **No audit trail**: there is no log of who accessed the file or when

## SSH Key Security

SSH private keys without a passphrase are equivalent to leaving your house key under the doormat. If someone gains access to your machine — through theft, malware, or a compromised backup — they immediately have access to every server that key authenticates to.

The `-----BEGIN OPENSSH PRIVATE KEY-----` header without an `ENCRYPTED` marker means the key is stored without any protection. Adding a passphrase with `ssh-keygen -p` encrypts the key at rest, meaning an attacker needs both the file and the passphrase to use it.

Use an SSH agent (`ssh-add`) to cache the decrypted key in memory so you only enter the passphrase once per session.

## Shell History as an Attack Vector

Shell history is an underestimated attack surface. Attackers who gain even brief access to a system routinely check history files for credentials. Red team operators list it as one of the first things they check during post-exploitation.

Commands that commonly leak secrets in history:

- `export SECRET_KEY=...` — sets environment variables
- `curl -H "Authorization: Bearer ..."` — API calls with tokens
- `mysql -u root -p'password'` — database connections
- `AWS_ACCESS_KEY_ID=... aws s3 ...` — inline AWS credentials
- `docker login -p ...` — container registry passwords

## AWS Credential Theft and Its Consequences

Compromised AWS credentials are among the most dangerous secrets to lose. Attackers use stolen credentials to:

- **Spin up cryptocurrency miners** — running hundreds of expensive GPU instances
- **Exfiltrate data** — downloading S3 buckets, RDS snapshots, and DynamoDB tables
- **Launch further attacks** — using your infrastructure as a pivot point
- **Destroy resources** — deleting backups and resources as ransom leverage

AWS bills from stolen credentials routinely reach tens of thousands of dollars. AWS may provide one-time courtesy credits, but there is no guarantee. The `~/.aws/credentials` file should be treated as critically sensitive.

## Concrete Steps to Protect Your Secrets

1. **Never hardcode secrets** — use environment variables, secret managers (Vault, AWS Secrets Manager, 1Password CLI), or encrypted configuration
2. **Configure .gitignore properly** — add `.env*`, `*.pem`, `*.key`, and credentials files before your first commit
3. **Use pre-commit hooks** — tools like `gitleaks`, `git-secrets`, or `trufflehog` scan for secrets before they reach the repository
4. **Protect SSH keys with passphrases** — run `ssh-keygen -p` on existing keys and use an SSH agent
5. **Use credential helpers for git** — `git config --global credential.helper osxkeychain` (macOS) or a similar helper for your OS
6. **Avoid secrets in shell history** — prefix sensitive commands with a space (requires `HISTCONTROL=ignorespace` in bash or `setopt HIST_IGNORE_SPACE` in zsh)
7. **Use aws-vault or AWS SSO** — never store long-lived AWS credentials in plaintext files
8. **Restrict file permissions** — `chmod 600` on all credential files, `chmod 700` on `~/.ssh`
9. **Audit regularly** — run this module periodically to catch new exposures
10. **Rotate compromised credentials immediately** — if a secret has been exposed, assume it has been captured and generate a new one

## Severity

**Critical** — Exposed secrets provide direct access to systems, data, and infrastructure. Unlike most tracking vectors, leaked credentials can result in immediate financial damage, data breaches, and complete system compromise.
