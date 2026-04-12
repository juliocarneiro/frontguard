# Changelog

## [0.1.0] - 2026-04-12

### Added
- Initial release
- XSS Scanner with 8 rules (innerHTML, eval, document.write, dangerouslySetInnerHTML, v-html, bypassSecurityTrust, outerHTML, javascript: URLs)
- Secrets Scanner with 149+ patterns (AWS, Google, GitHub, Stripe, Slack, Firebase, OpenAI, and more)
- Dependency Scanner with OSV.dev integration
- Auth Patterns Scanner (localStorage tokens, URL tokens, hardcoded credentials)
- Misconfig Scanner (sourcemaps, mixed content, insecure CDN)
- Live Vulnerability Feed (OSV.dev, GitHub Advisory DB, NVD) with SQLite cache
- AI-Powered Analysis module (OpenAI, Anthropic, Google, Ollama)
- Console, JSON, HTML Dashboard, and SARIF reporters
- GitHub Actions / CI/CD integration via SARIF
- Configurable rules and severity thresholds
