# FrontGuard — Complete Rule Catalog

Detailed reference for all 22 security rules in FrontGuard, organized by category.

---

## Summary

| Category | Rules | Focus |
|----------|-------|-------|
| [XSS Scanner](#xss-scanner) | FG-XSS-001 through FG-XSS-008 | Cross-Site Scripting |
| [Secrets Scanner](#secrets-scanner) | FG-SEC-001 through FG-SEC-006 | Secret leakage |
| [Dependency Scanner](#dependency-scanner) | FG-DEP-001, FG-DEP-002 | Vulnerable dependencies |
| [Auth Patterns Scanner](#auth-patterns-scanner) | FG-AUTH-001 through FG-AUTH-003 | Insecure authentication patterns |
| [Misconfig Scanner](#misconfig-scanner) | FG-CFG-001 through FG-CFG-003 | Security misconfigurations |

---

## XSS Scanner

Detects Cross-Site Scripting vulnerabilities using AST (Abstract Syntax Tree) analysis via Babel.

---

### FG-XSS-001 — Unsafe innerHTML Assignment

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-001` |
| **Severity** | `high` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | Direct assignment to `innerHTML` can cause XSS if the value contains unsanitized user input. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: user input directly assigned to innerHTML
const userInput = getQueryParam('name');
document.getElementById('greeting')!.innerHTML = userInput;
```

✅ **Secure Code:**

```typescript
// SAFE: use textContent for plain text
document.getElementById('greeting')!.textContent = userInput;

// SAFE: sanitize with DOMPurify when HTML is required
import DOMPurify from 'dompurify';
document.getElementById('content')!.innerHTML = DOMPurify.sanitize(userInput);
```

---

### FG-XSS-002 — Use of eval() or Similar Dynamic Code Execution

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-002` |
| **Severity** | `critical` |
| **CWE** | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) — Improper Neutralization of Directives in Dynamically Evaluated Code |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | `eval()`, `new Function()`, and `setTimeout`/`setInterval` with string arguments execute arbitrary code and can lead to code injection. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: eval executes arbitrary code
eval(userInput);

// DANGEROUS: new Function creates dynamic code
const fn = new Function('return ' + userExpression);

// DANGEROUS: setTimeout with string
setTimeout('alert("hello")', 1000);

// DANGEROUS: setInterval with string
setInterval('updateClock()', 1000);
```

✅ **Secure Code:**

```typescript
// SAFE: use JSON.parse for data
const data = JSON.parse(jsonString);

// SAFE: pass function reference to setTimeout
setTimeout(() => alert('hello'), 1000);

// SAFE: setInterval with reference
setInterval(updateClock, 1000);
```

---

### FG-XSS-003 — Use of document.write() or document.writeln()

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-003` |
| **Severity** | `high` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | `document.write()` and `document.writeln()` inject raw HTML into the page and are a common XSS vector. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: document.write with user data
document.write('<h1>' + userName + '</h1>');

// DANGEROUS: document.writeln
document.writeln('<script src="' + url + '"></script>');
```

✅ **Secure Code:**

```typescript
// SAFE: use DOM manipulation
const heading = document.createElement('h1');
heading.textContent = userName;
document.body.appendChild(heading);
```

---

### FG-XSS-004 — React dangerouslySetInnerHTML Usage

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-004` |
| **Severity** | `high` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | `dangerouslySetInnerHTML` bypasses React DOM's automatic escaping and can introduce XSS if the HTML is not sanitized. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: unsanitized user HTML
function Comment({ content }: { content: string }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}
```

✅ **Secure Code:**

```typescript
// SAFE: sanitize before rendering
import DOMPurify from 'dompurify';

function Comment({ content }: { content: string }) {
  const clean = DOMPurify.sanitize(content);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// BETTER: use plain text when possible
function Comment({ content }: { content: string }) {
  return <div>{content}</div>;
}
```

---

### FG-XSS-005 — Vue v-html Directive Usage

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-005` |
| **Severity** | `high` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | The `v-html` directive renders raw HTML and can lead to XSS when bound to unsanitized user input. |

❌ **Vulnerable Code:**

```html
<!-- DANGEROUS: v-html with user data -->
<template>
  <div v-html="userComment"></div>
</template>
```

✅ **Secure Code:**

```html
<!-- SAFE: use text interpolation -->
<template>
  <div>{{ userComment }}</div>
</template>

<!-- SAFE: sanitize before using v-html -->
<template>
  <div v-html="sanitizedComment"></div>
</template>

<script setup>
import DOMPurify from 'dompurify';
const sanitizedComment = computed(() => DOMPurify.sanitize(userComment.value));
</script>
```

---

### FG-XSS-006 — Angular Security Bypass (bypassSecurityTrust*)

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-006` |
| **Severity** | `critical` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | Angular's `DomSanitizer` `bypassSecurityTrust*` methods disable native XSS protection and should only be used with fully trusted content. |

Detected methods:
- `bypassSecurityTrustHtml`
- `bypassSecurityTrustScript`
- `bypassSecurityTrustUrl`
- `bypassSecurityTrustResourceUrl`
- `bypassSecurityTrustStyle`

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: bypass with user data
@Component({ template: '<div [innerHTML]="trustedHtml"></div>' })
export class UnsafeComponent {
  constructor(private sanitizer: DomSanitizer) {}

  get trustedHtml() {
    return this.sanitizer.bypassSecurityTrustHtml(this.userInput);
  }
}
```

✅ **Secure Code:**

```typescript
// SAFE: let Angular sanitize automatically
@Component({ template: '<div [innerHTML]="userInput"></div>' })
export class SafeComponent {
  userInput = '<b>text</b>';
}

// SAFE: use a Pipe with DOMPurify
@Pipe({ name: 'safeHtml' })
export class SafeHtmlPipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}
  transform(value: string) {
    const clean = DOMPurify.sanitize(value);
    return this.sanitizer.bypassSecurityTrustHtml(clean);
  }
}
```

---

### FG-XSS-007 — Unsafe outerHTML Assignment

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-007` |
| **Severity** | `high` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | Direct assignment to `outerHTML` replaces the element and its content with raw HTML, enabling XSS if the value is not sanitized. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: replacement with unsanitized HTML
element.outerHTML = '<div class="user">' + userInput + '</div>';
```

✅ **Secure Code:**

```typescript
// SAFE: use DOM APIs
const newEl = document.createElement('div');
newEl.className = 'user';
newEl.textContent = userInput;
element.replaceWith(newEl);
```

---

### FG-XSS-008 — Unsafe javascript: URL Scheme

| Field | Value |
|-------|-------|
| **ID** | `FG-XSS-008` |
| **Severity** | `medium` |
| **CWE** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **OWASP** | [A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/) |
| **Description** | `javascript:` URLs execute code when navigated and are a common XSS vector in `href`, `src`, and other attributes. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: javascript: in href
<a href="javascript:void(0)" onClick={handleClick}>Click</a>

// DANGEROUS: dynamic URL without validation
const url = userProvidedUrl; // could be "javascript:alert(1)"
window.location.href = url;
```

✅ **Secure Code:**

```typescript
// SAFE: use # or button for actions
<button onClick={handleClick}>Click</button>

// SAFE: validate URL scheme
function isSafeUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ['https:', 'http:', 'mailto:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}
```

---

## Secrets Scanner

Detects leaked secrets in code using 149+ regex patterns and Shannon entropy analysis.

---

### FG-SEC-001 — AWS Credentials Exposed

| Field | Value |
|-------|-------|
| **ID** | `FG-SEC-001` |
| **Severity** | `critical` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Use of Hard-coded Credentials |
| **OWASP** | [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Description** | AWS access keys or secret keys found in source code. These credentials grant direct access to AWS services and can compromise the entire account. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: hardcoded AWS credentials
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

const s3 = new AWS.S3({
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
});
```

✅ **Secure Code:**

```typescript
// SAFE: use environment variables
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

// SAFE: use AWS Secrets Manager or SSM Parameter Store
import { SecretsManager } from '@aws-sdk/client-secrets-manager';
const secret = await new SecretsManager({}).getSecretValue({ SecretId: 'my-credentials' });
```

---

### FG-SEC-002 — API Key or Token Exposed

| Field | Value |
|-------|-------|
| **ID** | `FG-SEC-002` |
| **Severity** | `high` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **OWASP** | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Description** | A known provider's API key or authentication token was found hardcoded in source code. |

Detected providers include: GitHub (`ghp_`, `gho_`, `ghs_`), Stripe (`sk_live_`, `sk_test_`, `pk_live_`), Slack (`xoxb-`, `xoxp-`), OpenAI (`sk-`), Anthropic (`sk-ant-`), Firebase, Google, npm, Docker Hub, Twilio, SendGrid, Azure, Supabase, and dozens more.

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: hardcoded tokens
const GITHUB_TOKEN = 'ghp_yourTokenHere1234';
const STRIPE_SECRET = 'sk_test_yourKeyHere';
const SLACK_BOT = 'xoxb-your-slack-token';
```

✅ **Secure Code:**

```typescript
// SAFE: environment variables
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;

// SAFE: secrets manager
import { getSecret } from './secrets-manager';
const slackToken = await getSecret('SLACK_BOT_TOKEN');
```

---

### FG-SEC-003 — Private Key Exposed

| Field | Value |
|-------|-------|
| **ID** | `FG-SEC-003` |
| **Severity** | `critical` |
| **CWE** | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) — Use of Hard-coded Cryptographic Key |
| **OWASP** | [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **Description** | A cryptographic private key (RSA, EC, DSA, PGP, or OpenSSH) was found in source code. Private keys must never be committed to repositories. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: private key in code
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;

// DANGEROUS: OpenSSH key in code
const SSH_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAA...
-----END OPENSSH PRIVATE KEY-----`;
```

✅ **Secure Code:**

```typescript
// SAFE: read from file with restricted permissions
import { readFileSync } from 'fs';
const privateKey = readFileSync('/etc/ssl/private/key.pem', 'utf-8');

// SAFE: environment variable (base64 encoded)
const privateKey = Buffer.from(process.env.PRIVATE_KEY_B64!, 'base64').toString();

// SAFE: secrets manager / vault
const key = await vault.getSecret('signing-key');
```

---

### FG-SEC-004 — Hardcoded JWT Token

| Field | Value |
|-------|-------|
| **ID** | `FG-SEC-004` |
| **Severity** | `high` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **OWASP** | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Description** | A JSON Web Token was found hardcoded in source code. JWTs often carry identity and authorization claims and must not be embedded in code. |

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: hardcoded JWT
const AUTH_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

fetch('/api/data', {
  headers: { Authorization: `Bearer ${AUTH_TOKEN}` }
});
```

✅ **Secure Code:**

```typescript
// SAFE: obtain token via authentication flow
const token = await authService.getAccessToken();

fetch('/api/data', {
  headers: { Authorization: `Bearer ${token}` }
});
```

---

### FG-SEC-005 — Database Connection String Exposed

| Field | Value |
|-------|-------|
| **ID** | `FG-SEC-005` |
| **Severity** | `critical` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **OWASP** | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Description** | A database connection string containing credentials was found in source code. This exposes the database host, user, and password. |

Detected databases: PostgreSQL, MongoDB, MySQL, Redis, MSSQL, JDBC.

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: connection strings with credentials
const PG_URL = 'postgresql://admin:s3cr3t@db.prod.com:5432/mydb';
const MONGO_URL = 'mongodb://root:password123@mongo.prod.com:27017/admin';
const REDIS_URL = 'redis://default:mypassword@redis.prod.com:6379';
```

✅ **Secure Code:**

```typescript
// SAFE: environment variables
const PG_URL = process.env.DATABASE_URL;
const MONGO_URL = process.env.MONGODB_URI;

// SAFE: build URI from secure components
const dbUrl = `postgresql://${process.env.DB_USER}:${process.env.DB_PASS}@${process.env.DB_HOST}:5432/${process.env.DB_NAME}`;
```

---

### FG-SEC-006 — High-Entropy String Detected

| Field | Value |
|-------|-------|
| **ID** | `FG-SEC-006` |
| **Severity** | `medium` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **OWASP** | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Description** | A high-entropy string resembling a secret or token was found. While it may be a false positive, high-entropy strings in source code often indicate leaked credentials. |

Detection uses Shannon entropy with a threshold of 4.5 bits per character on strings with 20+ characters.

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: high-entropy string that looks like an API key
const CONFIG_KEY = 'a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ';
```

✅ **Secure Code:**

```typescript
// SAFE: load from environment variable
const CONFIG_KEY = process.env.CONFIG_KEY;

// If the string is NOT a secret, add a comment or disable the rule
// frontguard-disable-next-line FG-SEC-006
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
```

---

## Dependency Scanner

Checks project dependencies against the OSV.dev database to find known vulnerabilities.

---

### FG-DEP-001 — Known Vulnerability in Dependency

| Field | Value |
|-------|-------|
| **ID** | `FG-DEP-001` |
| **Severity** | `high` |
| **CWE** | — |
| **OWASP** | [A06:2021 — Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) |
| **Description** | A known vulnerability (CVE) was found in a project dependency. |

❌ **Vulnerable:**

```json
{
  "dependencies": {
    "lodash": "4.17.20"
  }
}
```

✅ **Secure:**

```json
{
  "dependencies": {
    "lodash": "4.17.21"
  }
}
```

---

### FG-DEP-002 — Outdated Critical Dependency

| Field | Value |
|-------|-------|
| **ID** | `FG-DEP-002` |
| **Severity** | `medium` |
| **CWE** | — |
| **OWASP** | [A06:2021 — Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/) |
| **Description** | A critical project dependency is significantly outdated and may contain uncatalogued vulnerabilities. |

---

## Auth Patterns Scanner

Detects insecure authentication patterns using AST analysis.

---

### FG-AUTH-001 — Token Stored in Web Storage

| Field | Value |
|-------|-------|
| **ID** | `FG-AUTH-001` |
| **Severity** | `high` |
| **CWE** | [CWE-922](https://cwe.mitre.org/data/definitions/922.html) — Insecure Storage of Sensitive Information |
| **OWASP** | [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **Description** | Storing authentication tokens in `localStorage` or `sessionStorage` exposes them to XSS attacks. Any script running on the page can read these values. |

Detected sensitive keys: `token`, `jwt`, `auth`, `session`, `access_token`, `refresh_token`, `id_token`.

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: token in localStorage
localStorage.setItem('token', response.jwt);
localStorage.setItem('access_token', authResult.accessToken);

// DANGEROUS: token in sessionStorage
sessionStorage.setItem('authToken', token);
```

✅ **Secure Code:**

```typescript
// SAFE: use httpOnly cookies (configured on the backend)
// The token is sent automatically via cookie, never exposed to JS

// SAFE: in-memory storage for SPAs
class TokenStore {
  private token: string | null = null;

  setToken(t: string) { this.token = t; }
  getToken() { return this.token; }
  clear() { this.token = null; }
}
```

---

### FG-AUTH-002 — Token Passed in URL

| Field | Value |
|-------|-------|
| **ID** | `FG-AUTH-002` |
| **Severity** | `high` |
| **CWE** | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) — Use of GET Request Method With Sensitive Query Strings |
| **OWASP** | [A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) |
| **Description** | Passing authentication tokens or API keys in URL query parameters exposes them in browser history, server logs, and referrer headers. |

Detected parameters: `token`, `api_key`, `apikey`, `auth`, `jwt`, `access_token`, `secret`, `key`, `password`.

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: token in URL
const url = `https://api.example.com/data?access_token=${token}`;
fetch(`/api/resource?api_key=${apiKey}`);

const endpoint = `https://api.example.com/v1/users?token=${authToken}`;
```

✅ **Secure Code:**

```typescript
// SAFE: token in Authorization header
fetch('https://api.example.com/data', {
  headers: {
    'Authorization': `Bearer ${token}`,
  },
});

// SAFE: token in request body (POST)
fetch('/api/auth', {
  method: 'POST',
  body: JSON.stringify({ token: authToken }),
});
```

---

### FG-AUTH-003 — Hardcoded Credentials

| Field | Value |
|-------|-------|
| **ID** | `FG-AUTH-003` |
| **Severity** | `critical` |
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Use of Hard-coded Credentials |
| **OWASP** | [A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) |
| **Description** | Hardcoded passwords, secrets, or credentials in source code can be easily extracted and lead to unauthorized access. |

Detected variable names: `password`, `passwd`, `pwd`, `secret`, `secretkey`, `secret_key`, `secretKey`, `apiSecret`, `api_secret`, `privateKey`, `private_key`.

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: hardcoded credentials
const password = 'super_secret_123';
const secret = 'my-api-secret-key';

const config = {
  password: 'admin123',
  secret: 'production-secret',
  secretKey: 'sk-1234567890',
};
```

✅ **Secure Code:**

```typescript
// SAFE: environment variables
const password = process.env.DB_PASSWORD;
const secret = process.env.API_SECRET;

const config = {
  password: process.env.ADMIN_PASSWORD,
  secret: process.env.APP_SECRET,
  secretKey: process.env.SECRET_KEY,
};
```

---

## Misconfig Scanner

Detects security misconfigurations in configuration, build, and HTML files.

---

### FG-CFG-001 — Source Map Exposed in Production

| Field | Value |
|-------|-------|
| **ID** | `FG-CFG-001` |
| **Severity** | `medium` |
| **CWE** | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) — Inclusion of Sensitive Information in Source Code |
| **OWASP** | — |
| **Description** | Source maps expose the original source code, making it easier for attackers to find vulnerabilities in the application. |

Detected patterns:
- `//# sourceMappingURL=`
- `devtool: 'source-map'` or `devtool: 'eval-source-map'`
- `sourceMap: true`

❌ **Vulnerable Code:**

```typescript
// DANGEROUS: source map enabled in production
// webpack.config.js
module.exports = {
  devtool: 'source-map',
};

// tsconfig.json
{
  "compilerOptions": {
    "sourceMap": true
  }
}

// Bundle with source map reference
//# sourceMappingURL=bundle.js.map
```

✅ **Secure Code:**

```typescript
// SAFE: disable source maps in production
module.exports = {
  devtool: process.env.NODE_ENV === 'production' ? false : 'source-map',
};

// SAFE: use hidden source map (does not expose the URL)
module.exports = {
  devtool: 'hidden-source-map',
};
```

---

### FG-CFG-002 — Mixed Content (HTTP in HTTPS Context)

| Field | Value |
|-------|-------|
| **ID** | `FG-CFG-002` |
| **Severity** | `medium` |
| **CWE** | [CWE-311](https://cwe.mitre.org/data/definitions/311.html) — Missing Encryption of Sensitive Data |
| **OWASP** | — |
| **Description** | Loading resources over HTTP on an HTTPS page creates mixed content, allowing man-in-the-middle attacks on those resources. |

Exceptions: `localhost`, `127.0.0.1`, `0.0.0.0`, `[::1]` are ignored.

❌ **Vulnerable Code:**

```html
<!-- DANGEROUS: HTTP resources on HTTPS page -->
<script src="http://cdn.example.com/lib.js"></script>
<link href="http://fonts.example.com/font.css" rel="stylesheet">
<img src="http://images.example.com/logo.png" alt="Logo">
```

```typescript
// DANGEROUS: fetch over HTTP
fetch('http://api.example.com/data');
```

✅ **Secure Code:**

```html
<!-- SAFE: use HTTPS -->
<script src="https://cdn.example.com/lib.js"></script>
<link href="https://fonts.example.com/font.css" rel="stylesheet">

<!-- SAFE: use protocol-relative URL -->
<script src="//cdn.example.com/lib.js"></script>
```

---

### FG-CFG-003 — CDN Resource Without Integrity Check

| Field | Value |
|-------|-------|
| **ID** | `FG-CFG-003` |
| **Severity** | `low` |
| **CWE** | [CWE-353](https://cwe.mitre.org/data/definitions/353.html) — Missing Support for Integrity Check |
| **OWASP** | — |
| **Description** | External script or stylesheet loaded from a CDN without a Subresource Integrity (SRI) attribute. If the CDN is compromised, malicious code can be injected. |

Detected CDNs: `cdn.`, `unpkg`, `cdnjs`, `jsdelivr`, `ajax.googleapis`, `stackpath`, `maxcdn`, `fastly`, `cloudflare`.

❌ **Vulnerable Code:**

```html
<!-- DANGEROUS: CDN without SRI -->
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css" rel="stylesheet">
```

✅ **Secure Code:**

```html
<!-- SAFE: CDN with SRI -->
<script
  src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
  integrity="sha384-..."
  crossorigin="anonymous"
></script>

<link
  href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css"
  integrity="sha384-..."
  crossorigin="anonymous"
  rel="stylesheet"
>
```

---

## Summary by Severity

| Severity | Rules |
|----------|-------|
| **critical** | FG-XSS-002, FG-XSS-006, FG-SEC-001, FG-SEC-003, FG-SEC-005, FG-AUTH-003 |
| **high** | FG-XSS-001, FG-XSS-003, FG-XSS-004, FG-XSS-005, FG-XSS-007, FG-SEC-002, FG-SEC-004, FG-DEP-001, FG-AUTH-001, FG-AUTH-002 |
| **medium** | FG-XSS-008, FG-SEC-006, FG-DEP-002, FG-CFG-001, FG-CFG-002 |
| **low** | FG-CFG-003 |

**Total: 22 rules** covering XSS, secret leakage, vulnerable dependencies, insecure authentication, and misconfigurations.
