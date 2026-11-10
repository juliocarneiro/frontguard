# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems in FrontGuard itself.

Report them privately through
[GitHub security advisories](https://github.com/juliocarneiro/frontguard/security/advisories/new).
You should get a first response within 5 business days.

False negatives (a vulnerability FrontGuard should have caught) and false positives are not
security issues; please open a regular issue for those.

## Supported versions

Only the latest minor release receives fixes.

## Data handling

FrontGuard runs locally. The only network request is the optional dependency audit, which sends
package names and versions to [OSV.dev](https://osv.dev). Use `--offline` to disable it.
Secrets found during a scan are masked in every report.
