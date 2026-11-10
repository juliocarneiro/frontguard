import { calculateShannonEntropy } from './entropy.ts';

/** Words that show up as placeholder or label values next to "password", "token", etc. */
// prettier-ignore
const COMMON_VALUES: ReadonlySet<string> = new Set([
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

const ASSIGNED_VALUE_RE = /[:=]\s*['"`]([^'"`]+)['"`]/;

/** Extracts the quoted value assigned after `matchIndex`, e.g. `password: "x"` -> `x`. */
export function extractAssignedValue(line: string, matchIndex: number): string | null {
  return ASSIGNED_VALUE_RE.exec(line.slice(matchIndex))?.[1] ?? null;
}

/** Heuristic filter for generic patterns: rejects placeholders, labels, URLs and env lookups. */
export function looksLikeRealSecret(value: string): boolean {
  if (value.length < 8) return false;
  if (/\$\{|\{\{|%s|<[a-z]/i.test(value)) return false;

  const normalized = value.toLowerCase().replace(/[-_\s]/g, '');
  if (COMMON_VALUES.has(normalized) || COMMON_VALUES.has(value.toLowerCase())) return false;
  if (/^(x+|\*+|\.+|#+)$/i.test(value)) return false;
  if (/(your|example|sample|placeholder|changeme|dummy|xxxx|<redacted>)/i.test(value)) return false;
  if (/^[a-z]+$/i.test(value) && value.length < 16) return false;
  if (/^[a-z]+[_-][a-z]+$/i.test(value) && value.length < 20) return false;
  if (/^[a-z][a-zA-Z]+$/.test(value) && value.length < 20) return false;
  if (/^(https?|ftp|wss?):\/\//i.test(value)) return false;
  if (value.includes(' ') && value.split(' ').length > 3) return false;
  if (/^process\.env\b|^import\.meta\.env\b/.test(value)) return false;

  const entropy = calculateShannonEntropy(value);
  if (entropy < 3 && value.length < 24) return false;
  if (/^[A-Za-z0-9+/=_-]{16,}$/.test(value) && entropy >= 3.5) return true;
  if (value.length >= 20 && entropy >= 4) return true;
  return (
    entropy >= 3 &&
    value.length >= 12 &&
    /[A-Z]/.test(value) &&
    /[a-z]/.test(value) &&
    /\d/.test(value)
  );
}

const COMMENT_LINE_RE = /^\s*(?:\/\/|\/\*|\*|#|<!--)/;

/** Lines that are almost never real secrets for the generic/entropy checks. */
export function isNoisyLine(line: string): boolean {
  return (
    COMMENT_LINE_RE.test(line) ||
    /data:[\w-]+\/[\w+.-]+;base64,/i.test(line) ||
    /^\s*(?:import\s|export\s+type\s|interface\s|type\s+\w+\s*=)/.test(line) ||
    /^\s*(?:placeholder|label|aria-label|title|alt|name|autoComplete|htmlFor)\s*[=:]/.test(line) ||
    /type\s*=\s*["']password["']/.test(line) ||
    /\.(?:textContent|innerText|placeholder|label|title|alt|name)\s*=/.test(line)
  );
}

const SAFE_ENTROPY_CONTEXT_RE =
  /\b(?:className|class|style|src|href|id|d|viewBox|points|transform|integrity|nonce)\s*[=:]|\bdata-[\w-]+\s*=|\baria-[\w-]+\s*=|\bt\(|\bi18n|\bhash\b|\bsha\d|\bmd5\b|font-family|content-type|charset|encoding/i;

export function isSafeEntropyContext(line: string): boolean {
  return SAFE_ENTROPY_CONTEXT_RE.test(line);
}
