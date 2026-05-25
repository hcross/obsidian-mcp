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


## Remediated Vulnerabilities

### H-01 — Puppeteer SSRF / HTML Injection (Fixed in `security/fix-3-puppeteer`)

**Affected tools:** `export_note_pdf`, `export_vault_pdf`

**Attack surface:** Both tools launched a Chromium instance via Puppeteer with
no Content Security Policy, no network restrictions, and no sandbox arguments.
Note content was converted to HTML via `marked` without sanitization and passed
directly to `page.setContent()`. A crafted note could trigger outbound HTTP
requests (SSRF) or exfiltrate vault content via `fetch`, `<img src>`, or
`<link>` pointing to an attacker-controlled server.

**Remediation:** Both tools are disabled. They now return `isError: true` with
a message pointing users to safe alternatives:

- `export_note_pdf` → use `export_note_html` and convert to PDF locally with
  a sandboxed renderer (e.g., `wkhtmltopdf --disable-javascript`, Pandoc, or a
  local browser print dialog).
- `export_vault_pdf` → use `export_vault_markdown_bundle` or `export_vault_json`.

**`puppeteer` dependency** has been moved from `dependencies` to
`optionalDependencies` in `package.json`. It is not required for any active tool.
A future sandboxed PDF implementation must:

1. Launch Chromium with `--no-sandbox` blocked (run as non-root), `--disable-gpu`.
2. Use `page.setRequestInterception(true)` to block all non-data URLs.
3. Sanitize HTML through DOMPurify before passing to `page.setContent()`.
4. Set a strict CSP via `page.setExtraHTTPHeaders`.

Until that implementation lands, the tools remain disabled.

## Reporting

To report a security issue, please open a GitHub issue with the `security` label.
