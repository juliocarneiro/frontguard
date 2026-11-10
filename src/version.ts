import pkg from '../package.json' with { type: 'json' };

export const VERSION: string = pkg.version;
/** npm package name. The installed CLI command is always `frontguard`. */
export const PACKAGE_NAME: string = pkg.name;
export const HOMEPAGE = 'https://github.com/juliocarneiro/frontguard';
export const RULES_DOC_URL = `${HOMEPAGE}/blob/main/docs/rules.md`;
