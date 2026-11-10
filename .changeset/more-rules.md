---
'@juliocarneiro/frontguard': minor
---

8 new rules, based on recent frontend CVEs and incidents (31 in total):

- `FG-XSS-010` `no-open-redirect`: navigation to values from `location.search`/`hash`, `URLSearchParams`, `useSearchParams`, `document.referrer` (open redirect and `javascript:` XSS), with intra-file taint tracking
- `FG-XSS-011` `no-dangerous-attribute`: dynamic `on*` handlers and `srcdoc`, URL attributes fed from the address
- `FG-XSS-012` `no-prototype-pollution`: unguarded recursive merge/extend helpers and writes through `__proto__` (the bug class behind React2Shell, CVE-2025-55182, and recent DOMPurify bypasses)
- `FG-SEC-007` `no-secret-in-public-env`: server secrets behind `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `PUBLIC_`... prefixes
- `FG-AUTH-004` `no-insecure-random`: `Math.random()` for tokens, nonces, OAuth state, PKCE verifiers
- `FG-AUTH-005` `no-insecure-cookie`: auth cookies written from JavaScript
- `FG-CFG-005` `require-message-origin-check`: `message` listeners that never check `event.origin`
- `FG-CFG-006` `no-exposed-dev-server`: dev server host/CORS/fs protections disabled (Vite CVE-2025-30208, CVE-2025-31125, CVE-2025-24010)
