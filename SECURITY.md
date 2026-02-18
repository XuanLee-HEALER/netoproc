# Security Policy

## Supported Versions

<!-- TODO: fill in supported versions as releases are made -->

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in netoproc, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use one of these methods:

1. **GitHub Private Vulnerability Reporting**: Use the [Security Advisories](https://github.com/XuanLee-HEALER/netoproc/security/advisories/new) feature
2. **Email**: Send details to <!-- TODO: add security contact email -->

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Patch release**: Within 90 days (or sooner for critical issues)

## Scope

The following are in scope for security reports:

- Privilege escalation beyond what `sudo` grants
- Buffer overflows or memory safety issues in `unsafe` code
- BPF filter bypass that could leak sensitive packet data
- Denial of service through crafted packets
- Information disclosure through snapshot output

The following are **out of scope**:

- Issues that require root access to exploit (netoproc already runs as root)
- Denial of service through normal network flooding
- Issues in third-party dependencies (report upstream)
