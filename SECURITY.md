# Security Policy

capsurface runs against untrusted npm packages, and its output is meant to
be trusted enough to gate a CI pipeline. Vulnerabilities in it are treated
as high priority.

## Scope

In scope: the CLI (`bin/capsurface.js`) and library code (`lib/`) in this
repository, at any released version. This includes correctness bugs that
weaken the security guarantees described in the README, for example a way
to make `check` pass despite a real capability escalation, or a way for a
scanned package to affect the scanner's own execution or read or write
outside the scan target.

Out of scope: the limitations already documented in the README (for
example static analysis missing an obfuscated payload). Those are known
tradeoffs, not vulnerabilities, unless they turn out worse in practice
than documented.

## Reporting a vulnerability

Report privately rather than opening a public issue.

Preferred: use [GitHub's private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository, under the Security tab.

If that is not available to you, open an issue asking for a private
contact channel rather than describing the vulnerability publicly.

Include the version affected, a minimal reproduction (a package fixture
that triggers the issue works well given what this tool scans), and the
impact you believe it has.

## Response expectations

- Acknowledgement within 5 business days.
- Initial assessment (confirmed, not a vulnerability, or needs more info)
  within 10 business days.
- Fix or mitigation timeline communicated once the report is confirmed,
  scaled to severity.

## Disclosure

Coordinated disclosure. We agree on a disclosure date with the reporter
once a fix is available, credit the reporter unless they prefer otherwise,
and publish a GitHub Security Advisory alongside the fixed release.
