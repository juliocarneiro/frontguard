import type { Rule } from '../types.ts';
import { authRules } from './auth/index.ts';
import { misconfigRules } from './misconfig/index.ts';
import { secretsRules } from './secrets/index.ts';
import { xssRules } from './xss/index.ts';

/** Every rule that runs on source files. Dependency auditing is handled separately. */
export const builtinRules: readonly Rule[] = [
  ...xssRules,
  ...secretsRules,
  ...authRules,
  ...misconfigRules,
];
