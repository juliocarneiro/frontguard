import pkg from '../package.json' with { type: 'json' };

export const VERSION: string = pkg.version;
export const HOMEPAGE = 'https://github.com/juliocarneiro/frontguard';
export const RULES_DOC_URL = `${HOMEPAGE}/blob/main/docs/rules.md`;
