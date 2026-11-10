import type { Rule } from '../../types.ts';
import { noBypassSecurityTrust } from './no-bypass-security-trust.ts';
import { noDangerouslySetInnerHtml } from './no-dangerously-set-inner-html.ts';
import { noDocumentWrite } from './no-document-write.ts';
import { noEval } from './no-eval.ts';
import { noHtmlSinkCall } from './no-html-sink-call.ts';
import { noInnerHtml } from './no-inner-html.ts';
import { noJavascriptUrl } from './no-javascript-url.ts';
import { noSvelteHtml } from './no-svelte-html.ts';
import { noVHtml } from './no-v-html.ts';

export const xssRules: Rule[] = [
  noInnerHtml,
  noEval,
  noDocumentWrite,
  noDangerouslySetInnerHtml,
  noVHtml,
  noBypassSecurityTrust,
  noHtmlSinkCall,
  noJavascriptUrl,
  noSvelteHtml,
];
