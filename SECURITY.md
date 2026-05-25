# Security Policy

## Scope

This document tracks the security compliance work for the `obsidian-mcp` fork.
All fixes are tracked in the `security/compliance-baseline` branch and
consolidated in PR #1.

## Known Vulnerabilities (under remediation)

| ID | Severity | Issue |
|---|---|---|
| C-01/C-02/C-03/C-04 | CRITICAL | Path traversal & switchVault bypass |
| H-01 | HIGH | Puppeteer SSRF / exfiltration |
| H-02 | HIGH | Unrestricted export output_path |
| H-03 | HIGH | Permanent deletion without trash |
| H-04 | HIGH | ReDoS via user RegExp input |
| H-05/H-06 | HIGH | Mass destructive operations |
| M-01 | MEDIUM | YAML frontmatter injection |
| M-02 | MEDIUM | HTML export XSS |
| M-04/M-07 | MEDIUM | No rate limiting / Dataview timeout |
| M-05 | MEDIUM | System paths in error messages |
| M-08 | MEDIUM | No audit logging |

## Reporting

To report a security issue, please open a GitHub issue with the `security` label.
