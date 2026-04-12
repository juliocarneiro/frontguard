import type {
  FileContent,
  Finding,
  FrontGuardConfig,
  RuleDefinition,
  ScannerCategory,
} from '../../core/types.js';
import { BaseScanner } from '../base-scanner.js';
import { secretPatterns, type SecretPattern } from './patterns.js';
import { calculateShannonEntropy, isHighEntropy } from './entropy.js';

const RULES: RuleDefinition[] = [
  {
    id: 'FG-SEC-001',
    title: 'AWS Credentials Exposed',
    description: 'AWS access keys or secret keys found in source code. These credentials grant direct access to AWS services and can lead to full account compromise.',
    severity: 'critical',
    category: 'secrets',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    remediation: 'Remove the credentials from source code immediately, rotate the exposed keys in the AWS console, and use environment variables or a secrets manager (e.g. AWS Secrets Manager, SSM Parameter Store) instead.',
  },
  {
    id: 'FG-SEC-002',
    title: 'API Key or Token Exposed',
    description: 'A known provider API key or authentication token was found hardcoded in source code.',
    severity: 'high',
    category: 'secrets',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    remediation: 'Remove the key from source code, rotate it on the provider dashboard, and load it from environment variables or a secrets manager at runtime.',
  },
  {
    id: 'FG-SEC-003',
    title: 'Private Key Exposed',
    description: 'A private cryptographic key (RSA, EC, DSA, PGP, or OpenSSH) was found in source code. Private keys must never be committed to a repository.',
    severity: 'critical',
    category: 'secrets',
    cwe: 'CWE-321',
    owasp: 'A02:2021',
    remediation: 'Remove the private key from version control, revoke and regenerate it, and store it in a secure vault or file system with restricted permissions.',
  },
  {
    id: 'FG-SEC-004',
    title: 'Hardcoded JWT Token',
    description: 'A JSON Web Token was found hardcoded in source code. JWTs often carry identity and authorization claims and should not be embedded in code.',
    severity: 'high',
    category: 'secrets',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    remediation: 'Remove the JWT from source code. Tokens should be obtained at runtime via an authentication flow and stored securely (e.g. httpOnly cookies, secure session).',
  },
  {
    id: 'FG-SEC-005',
    title: 'Database Connection String Exposed',
    description: 'A database connection string containing credentials was found in source code. This exposes the database host, username, and password.',
    severity: 'critical',
    category: 'secrets',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    remediation: 'Remove the connection string from source code, rotate the database password, and provide it via environment variables or a secrets manager.',
  },
  {
    id: 'FG-SEC-006',
    title: 'High-Entropy String Detected',
    description: 'A high-entropy string resembling a secret or token was found. While this could be a false positive, high-entropy strings in source code often indicate leaked credentials.',
    severity: 'medium',
    category: 'secrets',
    cwe: 'CWE-798',
    owasp: 'A07:2021',
    remediation: 'Verify whether the flagged string is a credential. If so, remove it from source code and store it securely using environment variables or a secrets manager.',
  },
];

const rulesById = new Map(RULES.map((r) => [r.id, r]));

// ─── File-level skip ──────────────────────────────────────────────────────────

const SKIP_EXTENSIONS = new Set([
  '.lock', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff',
  '.woff2', '.ttf', '.eot', '.map', '.min.js', '.min.css', '.snap',
  '.md', '.mdx',
]);

function shouldSkipFile(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower.includes('node_modules') || lower.includes('.min.')) return true;
  const ext = lower.slice(lower.lastIndexOf('.'));
  if (SKIP_EXTENSIONS.has(ext)) return true;
  if (lower.includes('/locales/') || lower.includes('/i18n/') || lower.includes('/translations/')) return true;
  return false;
}

// ─── Line-level skip ──────────────────────────────────────────────────────────

const DATA_URI_RE = /data:\w+\/[\w+.-]+;base64,/i;
const REGEX_DEF_RE = /(?:regex|RegExp|new RegExp)\s*[:=(]/i;
const REGEX_INLINE_RE = /\/[^/]+\//;

const SKIP_LINE_PATTERNS = [
  /^\s*\/\//, // single-line comments
  /^\s*\*/, // multi-line comment body
  /^\s*\/\*/, // multi-line comment start
  /^\s*#/, // shell/yaml comments
  /^\s*(?:import|export\s+type|interface\s|type\s+\w+\s*=)/, // TS type/interface defs
  /^\s*(?:placeholder|label|aria-label|title|alt|name|autoComplete|htmlFor)\s*[=:]/, // HTML/JSX attributes
  /type\s*=\s*["']password["']/, // <input type="password">
  /\.(?:textContent|innerText|placeholder|label|title|alt|name)\s*=/, // DOM property assignments
];

function shouldSkipLine(line: string): boolean {
  if (DATA_URI_RE.test(line)) return true;
  if (REGEX_DEF_RE.test(line) || (REGEX_INLINE_RE.test(line) && line.includes('ruleId'))) return true;
  for (const p of SKIP_LINE_PATTERNS) {
    if (p.test(line)) return true;
  }
  return false;
}

// ─── Value validation for generic patterns ────────────────────────────────────

const COMMON_VALUES = new Set([
  'password', 'token', 'secret', 'key', 'auth', 'login', 'admin', 'root',
  'user', 'test', 'demo', 'example', 'sample', 'default', 'none', 'null',
  'undefined', 'true', 'false', 'email', 'username', 'name', 'value',
  'change', 'submit', 'reset', 'confirm', 'verify', 'update', 'delete',
  'create', 'read', 'write', 'edit', 'new', 'old', 'current', 'previous',
  'next', 'first', 'last', 'input', 'output', 'error', 'success', 'warning',
  'info', 'debug', 'trace', 'log', 'text', 'string', 'number', 'boolean',
  'object', 'array', 'function', 'class', 'type', 'interface', 'enum',
  'const', 'var', 'let', 'return', 'export', 'import', 'from', 'require',
  'module', 'config', 'settings', 'options', 'params', 'args', 'data',
  'result', 'response', 'request', 'body', 'header', 'headers', 'payload',
  'session', 'cookie', 'bearer', 'basic', 'oauth', 'refresh', 'access',
  'grant', 'scope', 'client', 'server', 'host', 'port', 'database', 'db',
  'api', 'url', 'uri', 'path', 'route', 'endpoint', 'method', 'status',
  'code', 'message', 'description', 'title', 'label', 'placeholder',
  'required', 'optional', 'hidden', 'visible', 'disabled', 'enabled',
  'active', 'inactive', 'loading', 'loaded', 'pending', 'complete',
  'public', 'private', 'protected', 'readonly', 'abstract', 'virtual',
  'override', 'static', 'final', 'super', 'this', 'self', 'void', 'never',
  'unknown', 'any', 'some', 'all', 'every', 'each', 'map', 'filter',
  'reduce', 'find', 'sort', 'index', 'count', 'length', 'size', 'empty',
  'full', 'open', 'close', 'start', 'stop', 'begin', 'end', 'init',
  'setup', 'teardown', 'before', 'after', 'step', 'stage', 'phase',
  'field', 'form', 'input_password', 'new_password', 'old_password',
  'confirm_password', 'current_password', 'password_confirmation',
  'your_password', 'enter_password', 'forgot_password', 'reset_password',
  'change_password', 'set_password', 'check_password', 'password_field',
  'password_input', 'password_label', 'password_placeholder',
  'access_token', 'refresh_token', 'id_token', 'auth_token', 'api_key',
  'secret_key', 'client_secret', 'client_id', 'grant_type',
  'authorization_code', 'password_grant', 'credentials', 'authenticate',
]);

const VALUE_EXTRACT_RE = /[:=]\s*['"]([^'"]+)['"]/;

function isGenericPattern(pattern: SecretPattern): boolean {
  return pattern.id.startsWith('generic-');
}

function extractValueFromMatch(line: string, matchIndex: number): string | null {
  const afterKey = line.slice(matchIndex);
  const m = VALUE_EXTRACT_RE.exec(afterKey);
  return m ? m[1] : null;
}

function looksLikeRealSecret(value: string): boolean {
  if (value.length < 8) return false;

  const lower = value.toLowerCase().replace(/[-_\s]/g, '');
  if (COMMON_VALUES.has(lower)) return false;
  if (COMMON_VALUES.has(value.toLowerCase())) return false;

  if (/^[a-z]+$/i.test(value) && value.length < 16) return false;

  if (/^[a-z]+[_-][a-z]+$/i.test(value) && value.length < 20) return false;

  if (/^(https?|ftp|ws|wss):\/\//i.test(value)) return false;

  if (value.includes(' ') && value.split(' ').length > 3) return false;

  if (/^[a-z][a-zA-Z]+$/.test(value) && value.length < 20) return false;

  if (/^process\.env\b/.test(value)) return false;

  const entropy = calculateShannonEntropy(value);
  if (entropy < 3.0 && value.length < 24) return false;

  if (/^[A-Za-z0-9+/=_-]{16,}$/.test(value) && entropy >= 3.5) return true;

  if (value.length >= 20 && entropy >= 4.0) return true;

  if (entropy >= 3.0 && value.length >= 12 && /[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value)) return true;

  return false;
}

// ─── High entropy string detection ────────────────────────────────────────────

const HIGH_ENTROPY_QUOTED_RE = /['"`]([A-Za-z0-9+/=_-]{20,})['"`]/g;

const SAFE_HIGH_ENTROPY_CONTEXTS = [
  /\bclassName\s*=/, /\bclass\s*=/, /\bstyle\s*=/,
  /\bsrc\s*=/, /\bhref\s*=/, /\bid\s*=/,
  /\bdata-[\w-]+\s*=/, /\baria-[\w-]+\s*=/,
  /\btranslate\b/, /\bt\(/, /\bi18n/,
  /\bHash\b/i, /\bsha\d/i, /\bmd5\b/i,
  /\bfont-family\b/, /\bcontent-type\b/i,
  /\bcharset\b/i, /\bencoding\b/i,
];

function isSafeEntropyContext(line: string): boolean {
  for (const re of SAFE_HIGH_ENTROPY_CONTEXTS) {
    if (re.test(line)) return true;
  }
  return false;
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

export class SecretsScanner extends BaseScanner {
  readonly name = 'Secrets Scanner';
  readonly category: ScannerCategory = 'secrets';

  getRules(): RuleDefinition[] {
    return RULES;
  }

  scanFile(file: FileContent, _config: FrontGuardConfig): Finding[] {
    if (shouldSkipFile(file.path)) return [];

    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (let i = 0; i < file.lines.length; i++) {
      const line = file.lines[i];
      const lineNum = i + 1;

      if (shouldSkipLine(line)) continue;

      for (const pattern of secretPatterns) {
        const rule = rulesById.get(pattern.ruleId);
        if (!rule) continue;

        pattern.regex.lastIndex = 0;
        const match = pattern.regex.exec(line);
        if (!match) continue;

        if (isGenericPattern(pattern)) {
          const value = extractValueFromMatch(line, match.index);
          if (!value || !looksLikeRealSecret(value)) continue;
        }

        const key = `${pattern.id}:${lineNum}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(this.createFinding(rule, file, lineNum, match.index + 1));
      }

      this.detectHighEntropyStrings(line, lineNum, file, findings, seen);
    }

    return findings;
  }

  private detectHighEntropyStrings(
    line: string,
    lineNum: number,
    file: FileContent,
    findings: Finding[],
    seen: Set<string>,
  ): void {
    if (isSafeEntropyContext(line)) return;

    HIGH_ENTROPY_QUOTED_RE.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = HIGH_ENTROPY_QUOTED_RE.exec(line)) !== null) {
      const candidate = match[1];
      if (candidate.length < 20) continue;
      if (!isHighEntropy(candidate)) continue;

      const key = `entropy:${lineNum}:${match.index}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const rule = rulesById.get('FG-SEC-006')!;
      findings.push(this.createFinding(rule, file, lineNum, match.index + 1));
    }
  }
}
