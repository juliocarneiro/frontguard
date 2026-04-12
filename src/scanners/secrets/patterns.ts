import type { Severity } from '../../core/types.js';

export interface SecretPattern {
  id: string;
  ruleId: string;
  name: string;
  regex: RegExp;
  severity: Severity;
}

export const secretPatterns: SecretPattern[] = [
  // ── AWS (FG-SEC-001) ──────────────────────────────────────────────
  { id: 'aws-access-key', ruleId: 'FG-SEC-001', name: 'AWS Access Key ID', regex: /(?:^|[^A-Za-z0-9/+=])(?:AKIA[0-9A-Z]{16})(?:$|[^A-Za-z0-9/+=])/, severity: 'critical' },
  { id: 'aws-secret-key', ruleId: 'FG-SEC-001', name: 'AWS Secret Access Key', regex: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/, severity: 'critical' },
  { id: 'aws-mws-key', ruleId: 'FG-SEC-001', name: 'AWS MWS Key', regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, severity: 'critical' },
  { id: 'aws-session-token', ruleId: 'FG-SEC-001', name: 'AWS Session Token', regex: /(?:aws_session_token|session_token)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?/, severity: 'critical' },
  { id: 'aws-account-id', ruleId: 'FG-SEC-001', name: 'AWS Account ID in ARN', regex: /arn:aws:[a-zA-Z0-9-]+:\w{2}-\w+-\d:\d{12}:[a-zA-Z0-9-/]+/, severity: 'critical' },

  // ── Google (FG-SEC-002) ───────────────────────────────────────────
  { id: 'google-api-key', ruleId: 'FG-SEC-002', name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/, severity: 'high' },
  { id: 'google-oauth-client-secret', ruleId: 'FG-SEC-002', name: 'Google OAuth Client Secret', regex: /GOCSPX-[A-Za-z0-9_-]{28}/, severity: 'high' },
  { id: 'google-cloud-sa-key', ruleId: 'FG-SEC-002', name: 'Google Cloud Service Account Key', regex: /"type"\s*:\s*"service_account"/, severity: 'high' },
  { id: 'google-oauth-access-token', ruleId: 'FG-SEC-002', name: 'Google OAuth Access Token', regex: /ya29\.[0-9A-Za-z_-]{50,}/, severity: 'high' },
  { id: 'google-oauth-refresh-token', ruleId: 'FG-SEC-002', name: 'Google OAuth Refresh Token', regex: /1\/[0-9A-Za-z_-]{43,}/, severity: 'high' },

  // ── GitHub (FG-SEC-002) ───────────────────────────────────────────
  { id: 'github-pat', ruleId: 'FG-SEC-002', name: 'GitHub Personal Access Token', regex: /ghp_[A-Za-z0-9]{36}/, severity: 'high' },
  { id: 'github-oauth-token', ruleId: 'FG-SEC-002', name: 'GitHub OAuth Token', regex: /gho_[A-Za-z0-9]{36}/, severity: 'high' },
  { id: 'github-user-token', ruleId: 'FG-SEC-002', name: 'GitHub User-to-Server Token', regex: /ghu_[A-Za-z0-9]{36}/, severity: 'high' },
  { id: 'github-server-token', ruleId: 'FG-SEC-002', name: 'GitHub Server-to-Server Token', regex: /ghs_[A-Za-z0-9]{36}/, severity: 'high' },
  { id: 'github-refresh-token', ruleId: 'FG-SEC-002', name: 'GitHub Refresh Token', regex: /ghr_[A-Za-z0-9]{36}/, severity: 'high' },
  { id: 'github-fine-grained-pat', ruleId: 'FG-SEC-002', name: 'GitHub Fine-Grained PAT', regex: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/, severity: 'high' },
  { id: 'github-app-token', ruleId: 'FG-SEC-002', name: 'GitHub App Token', regex: /(?:v[0-9]\.)(?:[0-9a-f]{8})-(?:[0-9a-f]{4})-(?:[0-9a-f]{4})-(?:[0-9a-f]{4})-(?:[0-9a-f]{12})/, severity: 'high' },

  // ── Stripe (FG-SEC-002) ───────────────────────────────────────────
  { id: 'stripe-secret-key-live', ruleId: 'FG-SEC-002', name: 'Stripe Secret Key (Live)', regex: /sk_live_[0-9a-zA-Z]{24,}/, severity: 'high' },
  { id: 'stripe-secret-key-test', ruleId: 'FG-SEC-002', name: 'Stripe Secret Key (Test)', regex: /sk_test_[0-9a-zA-Z]{24,}/, severity: 'high' },
  { id: 'stripe-publishable-key-live', ruleId: 'FG-SEC-002', name: 'Stripe Publishable Key (Live)', regex: /pk_live_[0-9a-zA-Z]{24,}/, severity: 'high' },
  { id: 'stripe-publishable-key-test', ruleId: 'FG-SEC-002', name: 'Stripe Publishable Key (Test)', regex: /pk_test_[0-9a-zA-Z]{24,}/, severity: 'high' },
  { id: 'stripe-restricted-key-live', ruleId: 'FG-SEC-002', name: 'Stripe Restricted Key (Live)', regex: /rk_live_[0-9a-zA-Z]{24,}/, severity: 'high' },
  { id: 'stripe-restricted-key-test', ruleId: 'FG-SEC-002', name: 'Stripe Restricted Key (Test)', regex: /rk_test_[0-9a-zA-Z]{24,}/, severity: 'high' },
  { id: 'stripe-webhook-secret', ruleId: 'FG-SEC-002', name: 'Stripe Webhook Secret', regex: /whsec_[0-9a-zA-Z]{24,}/, severity: 'high' },

  // ── Slack (FG-SEC-002) ────────────────────────────────────────────
  { id: 'slack-bot-token', ruleId: 'FG-SEC-002', name: 'Slack Bot Token', regex: /xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}/, severity: 'high' },
  { id: 'slack-user-token', ruleId: 'FG-SEC-002', name: 'Slack User Token', regex: /xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}/, severity: 'high' },
  { id: 'slack-legacy-token', ruleId: 'FG-SEC-002', name: 'Slack Legacy Token', regex: /xoxo-[0-9]{10,}-[A-Za-z0-9]{24,}/, severity: 'high' },
  { id: 'slack-app-token', ruleId: 'FG-SEC-002', name: 'Slack App Token', regex: /xoxa-[0-9]{10,}-[A-Za-z0-9]{24,}/, severity: 'high' },
  { id: 'slack-config-token', ruleId: 'FG-SEC-002', name: 'Slack Config Refresh Token', regex: /xoxr-[0-9]{10,}-[A-Za-z0-9]{24,}/, severity: 'high' },
  { id: 'slack-webhook', ruleId: 'FG-SEC-002', name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24,}/, severity: 'high' },

  // ── Firebase (FG-SEC-002) ─────────────────────────────────────────
  { id: 'firebase-api-key', ruleId: 'FG-SEC-002', name: 'Firebase API Key', regex: /(?:firebase|FIREBASE).*(?:api_?key|API_?KEY)\s*[:=]\s*['"]?AIza[0-9A-Za-z_-]{35}['"]?/, severity: 'high' },
  { id: 'firebase-url', ruleId: 'FG-SEC-002', name: 'Firebase Database URL', regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/, severity: 'high' },
  { id: 'firebase-service-account', ruleId: 'FG-SEC-002', name: 'Firebase Service Account', regex: /"project_id"\s*:\s*"[a-z0-9-]+"[\s\S]*"private_key"/, severity: 'high' },

  // ── OpenAI / Anthropic (FG-SEC-002) ───────────────────────────────
  { id: 'openai-api-key', ruleId: 'FG-SEC-002', name: 'OpenAI API Key', regex: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/, severity: 'high' },
  { id: 'openai-project-key', ruleId: 'FG-SEC-002', name: 'OpenAI Project API Key', regex: /sk-proj-[A-Za-z0-9_-]{40,}/, severity: 'high' },
  { id: 'anthropic-api-key', ruleId: 'FG-SEC-002', name: 'Anthropic API Key', regex: /sk-ant-[A-Za-z0-9_-]{40,}/, severity: 'high' },

  // ── npm (FG-SEC-002) ──────────────────────────────────────────────
  { id: 'npm-token', ruleId: 'FG-SEC-002', name: 'npm Access Token', regex: /npm_[A-Za-z0-9]{36}/, severity: 'high' },
  { id: 'npm-registry-auth', ruleId: 'FG-SEC-002', name: 'npm Registry Auth', regex: /_authToken\s*=\s*[A-Za-z0-9_-]{36,}/, severity: 'high' },

  // ── Docker Hub (FG-SEC-002) ───────────────────────────────────────
  { id: 'docker-hub-pat', ruleId: 'FG-SEC-002', name: 'Docker Hub Personal Access Token', regex: /dckr_pat_[A-Za-z0-9_-]{24,}/, severity: 'high' },
  { id: 'docker-hub-password', ruleId: 'FG-SEC-002', name: 'Docker Hub Password', regex: /(?:docker_password|DOCKER_PASSWORD)\s*[:=]\s*['"][^'"]{8,}['"]/, severity: 'high' },

  // ── Twilio (FG-SEC-002) ───────────────────────────────────────────
  { id: 'twilio-account-sid', ruleId: 'FG-SEC-002', name: 'Twilio Account SID', regex: /AC[0-9a-f]{32}/, severity: 'high' },
  { id: 'twilio-auth-token', ruleId: 'FG-SEC-002', name: 'Twilio Auth Token', regex: /(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[:=]\s*['"]?[0-9a-f]{32}['"]?/, severity: 'high' },

  // ── SendGrid (FG-SEC-002) ─────────────────────────────────────────
  { id: 'sendgrid-api-key', ruleId: 'FG-SEC-002', name: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, severity: 'high' },

  // ── Mailgun (FG-SEC-002) ──────────────────────────────────────────
  { id: 'mailgun-api-key', ruleId: 'FG-SEC-002', name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/, severity: 'high' },
  { id: 'mailgun-domain', ruleId: 'FG-SEC-002', name: 'Mailgun Domain Sending Key', regex: /(?:mailgun|MAILGUN).*(?:api_?key|API_?KEY)\s*[:=]\s*['"]?key-[0-9a-zA-Z]{32}['"]?/, severity: 'high' },

  // ── Heroku (FG-SEC-002) ───────────────────────────────────────────
  { id: 'heroku-api-key', ruleId: 'FG-SEC-002', name: 'Heroku API Key', regex: /(?:heroku_api_key|HEROKU_API_KEY)\s*[:=]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]?/, severity: 'high' },
  { id: 'heroku-oauth-token', ruleId: 'FG-SEC-002', name: 'Heroku OAuth Token', regex: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=.*heroku)/i, severity: 'high' },

  // ── DigitalOcean (FG-SEC-002) ─────────────────────────────────────
  { id: 'digitalocean-pat', ruleId: 'FG-SEC-002', name: 'DigitalOcean Personal Access Token', regex: /dop_v1_[0-9a-f]{64}/, severity: 'high' },
  { id: 'digitalocean-oauth', ruleId: 'FG-SEC-002', name: 'DigitalOcean OAuth Token', regex: /doo_v1_[0-9a-f]{64}/, severity: 'high' },
  { id: 'digitalocean-refresh', ruleId: 'FG-SEC-002', name: 'DigitalOcean Refresh Token', regex: /dor_v1_[0-9a-f]{64}/, severity: 'high' },

  // ── Azure (FG-SEC-002) ────────────────────────────────────────────
  { id: 'azure-storage-key', ruleId: 'FG-SEC-002', name: 'Azure Storage Account Key', regex: /(?:AccountKey|azure_storage_key|AZURE_STORAGE_KEY)\s*[:=]\s*['"]?[A-Za-z0-9+/]{86}==['"]?/, severity: 'high' },
  { id: 'azure-ad-client-secret', ruleId: 'FG-SEC-002', name: 'Azure AD Client Secret', regex: /(?:azure_client_secret|AZURE_CLIENT_SECRET|client_secret)\s*[:=]\s*['"]?[A-Za-z0-9~._-]{34,}['"]?/, severity: 'high' },
  { id: 'azure-connection-string', ruleId: 'FG-SEC-002', name: 'Azure Connection String', regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==/, severity: 'high' },
  { id: 'azure-sas-token', ruleId: 'FG-SEC-002', name: 'Azure SAS Token', regex: /[?&]sig=[A-Za-z0-9%+/]{43,}%3D/, severity: 'high' },

  // ── Supabase (FG-SEC-002) ─────────────────────────────────────────
  { id: 'supabase-anon-key', ruleId: 'FG-SEC-002', name: 'Supabase Anon Key', regex: /(?:supabase_anon_key|SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY)\s*[:=]\s*['"]?eyJ[A-Za-z0-9_-]{100,}['"]?/, severity: 'high' },
  { id: 'supabase-service-role', ruleId: 'FG-SEC-002', name: 'Supabase Service Role Key', regex: /(?:supabase_service_role|SUPABASE_SERVICE_ROLE_KEY)\s*[:=]\s*['"]?eyJ[A-Za-z0-9_-]{100,}['"]?/, severity: 'high' },

  // ── PayPal (FG-SEC-002) ───────────────────────────────────────────
  { id: 'paypal-client-id', ruleId: 'FG-SEC-002', name: 'PayPal Client ID', regex: /(?:paypal_client_id|PAYPAL_CLIENT_ID)\s*[:=]\s*['"]?A[A-Za-z0-9_-]{40,}['"]?/, severity: 'high' },
  { id: 'paypal-secret', ruleId: 'FG-SEC-002', name: 'PayPal Client Secret', regex: /(?:paypal_secret|PAYPAL_SECRET|PAYPAL_CLIENT_SECRET)\s*[:=]\s*['"]?E[A-Za-z0-9_-]{40,}['"]?/, severity: 'high' },
  { id: 'paypal-braintree', ruleId: 'FG-SEC-002', name: 'PayPal Braintree Token', regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/, severity: 'high' },

  // ── Shopify (FG-SEC-002) ──────────────────────────────────────────
  { id: 'shopify-api-key', ruleId: 'FG-SEC-002', name: 'Shopify API Key', regex: /shpat_[0-9a-fA-F]{32}/, severity: 'high' },
  { id: 'shopify-shared-secret', ruleId: 'FG-SEC-002', name: 'Shopify Shared Secret', regex: /shpss_[0-9a-fA-F]{32}/, severity: 'high' },
  { id: 'shopify-access-token', ruleId: 'FG-SEC-002', name: 'Shopify Access Token', regex: /shpca_[0-9a-fA-F]{32}/, severity: 'high' },
  { id: 'shopify-private-app', ruleId: 'FG-SEC-002', name: 'Shopify Private App Password', regex: /shppa_[0-9a-fA-F]{32}/, severity: 'high' },

  // ── Algolia (FG-SEC-002) ──────────────────────────────────────────
  { id: 'algolia-api-key', ruleId: 'FG-SEC-002', name: 'Algolia API Key', regex: /(?:algolia_api_key|ALGOLIA_API_KEY|algolia_admin_key)\s*[:=]\s*['"]?[0-9a-f]{32}['"]?/, severity: 'high' },
  { id: 'algolia-app-id', ruleId: 'FG-SEC-002', name: 'Algolia Application ID', regex: /(?:algolia_app_id|ALGOLIA_APP_ID|ALGOLIA_APPLICATION_ID)\s*[:=]\s*['"]?[A-Z0-9]{10}['"]?/, severity: 'high' },

  // ── Datadog (FG-SEC-002) ──────────────────────────────────────────
  { id: 'datadog-api-key', ruleId: 'FG-SEC-002', name: 'Datadog API Key', regex: /(?:datadog_api_key|DD_API_KEY|DATADOG_API_KEY)\s*[:=]\s*['"]?[0-9a-f]{32}['"]?/, severity: 'high' },
  { id: 'datadog-app-key', ruleId: 'FG-SEC-002', name: 'Datadog Application Key', regex: /(?:datadog_app_key|DD_APP_KEY|DATADOG_APP_KEY)\s*[:=]\s*['"]?[0-9a-f]{40}['"]?/, severity: 'high' },

  // ── PagerDuty (FG-SEC-002) ────────────────────────────────────────
  { id: 'pagerduty-api-key', ruleId: 'FG-SEC-002', name: 'PagerDuty API Key', regex: /(?:pagerduty_api_key|PAGERDUTY_API_KEY|pagerduty_token)\s*[:=]\s*['"]?[A-Za-z0-9+/]{20,}['"]?/, severity: 'high' },
  { id: 'pagerduty-integration-key', ruleId: 'FG-SEC-002', name: 'PagerDuty Integration Key', regex: /(?:pagerduty_integration_key|PAGERDUTY_INTEGRATION_KEY)\s*[:=]\s*['"]?[0-9a-f]{32}['"]?/, severity: 'high' },

  // ── CircleCI (FG-SEC-002) ─────────────────────────────────────────
  { id: 'circleci-token', ruleId: 'FG-SEC-002', name: 'CircleCI Personal Token', regex: /(?:circle_token|CIRCLE_TOKEN|circleci_token|CIRCLECI_TOKEN)\s*[:=]\s*['"]?[0-9a-f]{40}['"]?/, severity: 'high' },
  { id: 'circleci-api-token', ruleId: 'FG-SEC-002', name: 'CircleCI API Token v2', regex: /CIRCLE.*TOKEN.*['"]?[0-9a-fA-F]{40}['"]?/, severity: 'high' },

  // ── Travis CI (FG-SEC-002) ────────────────────────────────────────
  { id: 'travis-token', ruleId: 'FG-SEC-002', name: 'Travis CI Token', regex: /(?:travis_token|TRAVIS_TOKEN|travis_api_token)\s*[:=]\s*['"]?[A-Za-z0-9]{20,}['"]?/, severity: 'high' },

  // ── Bitbucket (FG-SEC-002) ────────────────────────────────────────
  { id: 'bitbucket-app-password', ruleId: 'FG-SEC-002', name: 'Bitbucket App Password', regex: /(?:bitbucket_password|BITBUCKET_PASSWORD|bitbucket_app_password)\s*[:=]\s*['"]?[A-Za-z0-9]{18,}['"]?/, severity: 'high' },
  { id: 'bitbucket-oauth-secret', ruleId: 'FG-SEC-002', name: 'Bitbucket OAuth Secret', regex: /(?:bitbucket_client_secret|BITBUCKET_CLIENT_SECRET)\s*[:=]\s*['"]?[A-Za-z0-9]{32,}['"]?/, severity: 'high' },

  // ── GitLab (FG-SEC-002) ───────────────────────────────────────────
  { id: 'gitlab-pat', ruleId: 'FG-SEC-002', name: 'GitLab Personal Access Token', regex: /glpat-[A-Za-z0-9_-]{20,}/, severity: 'high' },
  { id: 'gitlab-pipeline-token', ruleId: 'FG-SEC-002', name: 'GitLab Pipeline Token', regex: /glptt-[A-Za-z0-9_-]{20,}/, severity: 'high' },
  { id: 'gitlab-runner-token', ruleId: 'FG-SEC-002', name: 'GitLab Runner Registration Token', regex: /GR1348941[A-Za-z0-9_-]{20,}/, severity: 'high' },

  // ── Discord (FG-SEC-002) ──────────────────────────────────────────
  { id: 'discord-bot-token', ruleId: 'FG-SEC-002', name: 'Discord Bot Token', regex: /(?:discord_token|DISCORD_TOKEN|DISCORD_BOT_TOKEN)\s*[:=]\s*['"]?[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}['"]?/, severity: 'high' },
  { id: 'discord-webhook', ruleId: 'FG-SEC-002', name: 'Discord Webhook URL', regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/, severity: 'high' },

  // ── Telegram (FG-SEC-002) ─────────────────────────────────────────
  { id: 'telegram-bot-token', ruleId: 'FG-SEC-002', name: 'Telegram Bot Token', regex: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/, severity: 'high' },

  // ── Mapbox (FG-SEC-002) ───────────────────────────────────────────
  { id: 'mapbox-public-token', ruleId: 'FG-SEC-002', name: 'Mapbox Public Access Token', regex: /pk\.[A-Za-z0-9]{60,}/, severity: 'high' },
  { id: 'mapbox-secret-token', ruleId: 'FG-SEC-002', name: 'Mapbox Secret Access Token', regex: /sk\.[A-Za-z0-9]{60,}/, severity: 'high' },

  // ── Cloudflare (FG-SEC-002) ───────────────────────────────────────
  { id: 'cloudflare-api-key', ruleId: 'FG-SEC-002', name: 'Cloudflare API Key', regex: /(?:cloudflare_api_key|CF_API_KEY|CLOUDFLARE_API_KEY)\s*[:=]\s*['"]?[0-9a-f]{37}['"]?/, severity: 'high' },
  { id: 'cloudflare-api-token', ruleId: 'FG-SEC-002', name: 'Cloudflare API Token', regex: /(?:cloudflare_api_token|CF_API_TOKEN)\s*[:=]\s*['"]?[A-Za-z0-9_-]{40}['"]?/, severity: 'high' },
  { id: 'cloudflare-origin-ca', ruleId: 'FG-SEC-002', name: 'Cloudflare Origin CA Key', regex: /v1\.0-[0-9a-f]{24}-[0-9a-f]{146}/, severity: 'high' },

  // ── Sentry (FG-SEC-002) ───────────────────────────────────────────
  { id: 'sentry-dsn', ruleId: 'FG-SEC-002', name: 'Sentry DSN', regex: /https:\/\/[0-9a-f]{32}@(?:o[0-9]+\.)?(?:sentry\.io|[^/]+)\/[0-9]+/, severity: 'high' },
  { id: 'sentry-auth-token', ruleId: 'FG-SEC-002', name: 'Sentry Auth Token', regex: /(?:sentry_auth_token|SENTRY_AUTH_TOKEN)\s*[:=]\s*['"]?[0-9a-f]{64}['"]?/, severity: 'high' },

  // ── New Relic (FG-SEC-002) ────────────────────────────────────────
  { id: 'newrelic-license-key', ruleId: 'FG-SEC-002', name: 'New Relic License Key', regex: /(?:new_relic_license_key|NEWRELIC_LICENSE_KEY|NEW_RELIC_LICENSE_KEY)\s*[:=]\s*['"]?[0-9a-f]{40}['"]?/, severity: 'high' },
  { id: 'newrelic-api-key', ruleId: 'FG-SEC-002', name: 'New Relic API Key', regex: /NRAK-[A-Z0-9]{27}/, severity: 'high' },
  { id: 'newrelic-insights-key', ruleId: 'FG-SEC-002', name: 'New Relic Insights Key', regex: /NRI[a-zA-Z0-9-]{32,}/, severity: 'high' },

  // ── Elastic Cloud (FG-SEC-002) ────────────────────────────────────
  { id: 'elastic-cloud-id', ruleId: 'FG-SEC-002', name: 'Elastic Cloud ID', regex: /(?:elastic_cloud_id|ELASTIC_CLOUD_ID|CLOUD_ID)\s*[:=]\s*['"]?[A-Za-z0-9_:.-]{50,}['"]?/, severity: 'high' },
  { id: 'elastic-api-key', ruleId: 'FG-SEC-002', name: 'Elastic API Key', regex: /(?:elastic_api_key|ELASTIC_API_KEY)\s*[:=]\s*['"]?[A-Za-z0-9=_-]{40,}['"]?/, severity: 'high' },

  // ── Private Keys (FG-SEC-003) ─────────────────────────────────────
  { id: 'rsa-private-key', ruleId: 'FG-SEC-003', name: 'RSA Private Key', regex: /-----BEGIN RSA PRIVATE KEY-----/, severity: 'critical' },
  { id: 'openssh-private-key', ruleId: 'FG-SEC-003', name: 'OpenSSH Private Key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/, severity: 'critical' },
  { id: 'ec-private-key', ruleId: 'FG-SEC-003', name: 'EC Private Key', regex: /-----BEGIN EC PRIVATE KEY-----/, severity: 'critical' },
  { id: 'pgp-private-key', ruleId: 'FG-SEC-003', name: 'PGP Private Key', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, severity: 'critical' },
  { id: 'dsa-private-key', ruleId: 'FG-SEC-003', name: 'DSA Private Key', regex: /-----BEGIN DSA PRIVATE KEY-----/, severity: 'critical' },
  { id: 'generic-private-key', ruleId: 'FG-SEC-003', name: 'Generic Private Key', regex: /-----BEGIN PRIVATE KEY-----/, severity: 'critical' },
  { id: 'encrypted-private-key', ruleId: 'FG-SEC-003', name: 'Encrypted Private Key', regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/, severity: 'critical' },
  { id: 'pkcs8-private-key', ruleId: 'FG-SEC-003', name: 'PKCS8 Private Key', regex: /-----BEGIN PKCS8 PRIVATE KEY-----/, severity: 'critical' },
  { id: 'ssh-rsa-key', ruleId: 'FG-SEC-003', name: 'SSH Private Key Content', regex: /ssh-rsa\s+AAAA[A-Za-z0-9+/=]{100,}/, severity: 'critical' },

  // ── JWT (FG-SEC-004) ──────────────────────────────────────────────
  { id: 'jwt-token', ruleId: 'FG-SEC-004', name: 'Hardcoded JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'high' },
  { id: 'jwt-base64-header', ruleId: 'FG-SEC-004', name: 'JWT Base64 Header', regex: /['"]eyJ(?:hbGci|0eXAi)[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+['"]/, severity: 'high' },

  // ── Database Connection Strings (FG-SEC-005) ──────────────────────
  { id: 'postgres-uri', ruleId: 'FG-SEC-005', name: 'PostgreSQL Connection String', regex: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^/\s]+\/[^\s'"]+/, severity: 'critical' },
  { id: 'mongodb-uri', ruleId: 'FG-SEC-005', name: 'MongoDB Connection String', regex: /mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^/\s]+/, severity: 'critical' },
  { id: 'mysql-uri', ruleId: 'FG-SEC-005', name: 'MySQL Connection String', regex: /mysql:\/\/[^:\s]+:[^@\s]+@[^/\s]+\/[^\s'"]+/, severity: 'critical' },
  { id: 'redis-uri', ruleId: 'FG-SEC-005', name: 'Redis Connection String', regex: /redis(?:s)?:\/\/[^:\s]*:[^@\s]+@[^/\s]+/, severity: 'critical' },
  { id: 'mssql-uri', ruleId: 'FG-SEC-005', name: 'MSSQL Connection String', regex: /Server=[^;]+;.*Password=[^;]+/i, severity: 'critical' },
  { id: 'jdbc-uri', ruleId: 'FG-SEC-005', name: 'JDBC Connection String', regex: /jdbc:[a-z]+:\/\/[^:\s]+:[^@\s]+@[^/\s]+/, severity: 'critical' },

  // ── Generic Secrets (FG-SEC-002) ──────────────────────────────────
  { id: 'generic-password', ruleId: 'FG-SEC-002', name: 'Hardcoded Password', regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/i, severity: 'high' },
  { id: 'generic-secret', ruleId: 'FG-SEC-002', name: 'Hardcoded Secret', regex: /(?:secret|SECRET)\s*[:=]\s*['"][^'"]{8,}['"]/, severity: 'high' },
  { id: 'generic-api-key', ruleId: 'FG-SEC-002', name: 'Hardcoded API Key', regex: /(?:api_key|apiKey|API_KEY|ApiKey)\s*[:=]\s*['"][^'"]{8,}['"]/, severity: 'high' },
  { id: 'generic-access-token', ruleId: 'FG-SEC-002', name: 'Hardcoded Access Token', regex: /(?:access_token|ACCESS_TOKEN|accessToken)\s*[:=]\s*['"][^'"]{16,}['"]/, severity: 'high' },
  { id: 'generic-auth-token', ruleId: 'FG-SEC-002', name: 'Hardcoded Auth Token', regex: /(?:auth_token|AUTH_TOKEN|authToken)\s*[:=]\s*['"][^'"]{16,}['"]/, severity: 'high' },
  { id: 'generic-client-secret', ruleId: 'FG-SEC-002', name: 'Hardcoded Client Secret', regex: /(?:client_secret|CLIENT_SECRET|clientSecret)\s*[:=]\s*['"][^'"]{8,}['"]/, severity: 'high' },
  { id: 'generic-private-key-value', ruleId: 'FG-SEC-002', name: 'Hardcoded Private Key Value', regex: /(?:private_key|PRIVATE_KEY|privateKey)\s*[:=]\s*['"][^'"]{20,}['"]/, severity: 'high' },
  { id: 'generic-encryption-key', ruleId: 'FG-SEC-002', name: 'Hardcoded Encryption Key', regex: /(?:encryption_key|ENCRYPTION_KEY|encryptionKey)\s*[:=]\s*['"][^'"]{8,}['"]/, severity: 'high' },
  { id: 'generic-signing-key', ruleId: 'FG-SEC-002', name: 'Hardcoded Signing Key', regex: /(?:signing_key|SIGNING_KEY|signingKey)\s*[:=]\s*['"][^'"]{8,}['"]/, severity: 'high' },
  { id: 'generic-bearer-token', ruleId: 'FG-SEC-002', name: 'Hardcoded Bearer Token', regex: /['"]Bearer\s+[A-Za-z0-9_-]{20,}['"]/, severity: 'high' },
  { id: 'generic-basic-auth', ruleId: 'FG-SEC-002', name: 'Hardcoded Basic Auth', regex: /['"]Basic\s+[A-Za-z0-9+/=]{20,}['"]/, severity: 'high' },
  { id: 'generic-authorization-header', ruleId: 'FG-SEC-002', name: 'Hardcoded Authorization Header', regex: /(?:authorization|Authorization)\s*[:=]\s*['"][^'"]{20,}['"]/, severity: 'high' },

  // ── Vercel (FG-SEC-002) ───────────────────────────────────────────
  { id: 'vercel-token', ruleId: 'FG-SEC-002', name: 'Vercel Access Token', regex: /(?:vercel_token|VERCEL_TOKEN)\s*[:=]\s*['"]?[A-Za-z0-9]{24,}['"]?/, severity: 'high' },

  // ── Netlify (FG-SEC-002) ──────────────────────────────────────────
  { id: 'netlify-token', ruleId: 'FG-SEC-002', name: 'Netlify Access Token', regex: /(?:netlify_token|NETLIFY_AUTH_TOKEN|NETLIFY_TOKEN)\s*[:=]\s*['"]?[A-Za-z0-9_-]{40,}['"]?/, severity: 'high' },

  // ── HashiCorp Vault (FG-SEC-002) ──────────────────────────────────
  { id: 'vault-token', ruleId: 'FG-SEC-002', name: 'HashiCorp Vault Token', regex: /(?:vault_token|VAULT_TOKEN)\s*[:=]\s*['"]?(?:s\.|hvs\.)[A-Za-z0-9_-]{24,}['"]?/, severity: 'high' },
  { id: 'vault-batch-token', ruleId: 'FG-SEC-002', name: 'HashiCorp Vault Batch Token', regex: /hvb\.[A-Za-z0-9_-]{100,}/, severity: 'high' },

  // ── Confluent / Kafka (FG-SEC-002) ────────────────────────────────
  { id: 'confluent-api-key', ruleId: 'FG-SEC-002', name: 'Confluent API Key', regex: /(?:confluent_api_key|CONFLUENT_API_KEY)\s*[:=]\s*['"]?[A-Z0-9]{16}['"]?/, severity: 'high' },
  { id: 'confluent-api-secret', ruleId: 'FG-SEC-002', name: 'Confluent API Secret', regex: /(?:confluent_api_secret|CONFLUENT_API_SECRET)\s*[:=]\s*['"]?[A-Za-z0-9+/]{64}['"]?/, severity: 'high' },

  // ── Okta (FG-SEC-002) ─────────────────────────────────────────────
  { id: 'okta-api-token', ruleId: 'FG-SEC-002', name: 'Okta API Token', regex: /(?:okta_api_token|OKTA_API_TOKEN)\s*[:=]\s*['"]?00[A-Za-z0-9_-]{40,}['"]?/, severity: 'high' },
  { id: 'okta-client-secret', ruleId: 'FG-SEC-002', name: 'Okta Client Secret', regex: /(?:okta_client_secret|OKTA_CLIENT_SECRET)\s*[:=]\s*['"]?[A-Za-z0-9_-]{40,}['"]?/, severity: 'high' },

  // ── Auth0 (FG-SEC-002) ────────────────────────────────────────────
  { id: 'auth0-client-secret', ruleId: 'FG-SEC-002', name: 'Auth0 Client Secret', regex: /(?:auth0_client_secret|AUTH0_CLIENT_SECRET)\s*[:=]\s*['"]?[A-Za-z0-9_-]{40,}['"]?/, severity: 'high' },
  { id: 'auth0-management-token', ruleId: 'FG-SEC-002', name: 'Auth0 Management API Token', regex: /(?:auth0_management_token|AUTH0_MANAGEMENT_API_TOKEN)\s*[:=]\s*['"]?eyJ[A-Za-z0-9_-]+['"]?/, severity: 'high' },

  // ── Linear (FG-SEC-002) ───────────────────────────────────────────
  { id: 'linear-api-key', ruleId: 'FG-SEC-002', name: 'Linear API Key', regex: /lin_api_[A-Za-z0-9]{40,}/, severity: 'high' },

  // ── Doppler (FG-SEC-002) ──────────────────────────────────────────
  { id: 'doppler-token', ruleId: 'FG-SEC-002', name: 'Doppler Service Token', regex: /dp\.st\.[a-z0-9_-]{2,}\.[A-Za-z0-9]{40,}/, severity: 'high' },

  // ── Dynatrace (FG-SEC-002) ────────────────────────────────────────
  { id: 'dynatrace-api-token', ruleId: 'FG-SEC-002', name: 'Dynatrace API Token', regex: /dt0c01\.[A-Z0-9]{24}\.[A-Za-z0-9]{64}/, severity: 'high' },

  // ── Grafana (FG-SEC-002) ──────────────────────────────────────────
  { id: 'grafana-api-key', ruleId: 'FG-SEC-002', name: 'Grafana API Key', regex: /eyJrIjoi[A-Za-z0-9+/]{28,}={0,2}/, severity: 'high' },
  { id: 'grafana-cloud-token', ruleId: 'FG-SEC-002', name: 'Grafana Cloud Token', regex: /glc_[A-Za-z0-9_-]{32,}/, severity: 'high' },
  { id: 'grafana-service-account', ruleId: 'FG-SEC-002', name: 'Grafana Service Account Token', regex: /glsa_[A-Za-z0-9_-]{32,}/, severity: 'high' },

  // ── Postman (FG-SEC-002) ──────────────────────────────────────────
  { id: 'postman-api-key', ruleId: 'FG-SEC-002', name: 'Postman API Key', regex: /PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}/, severity: 'high' },

  // ── Pulumi (FG-SEC-002) ───────────────────────────────────────────
  { id: 'pulumi-access-token', ruleId: 'FG-SEC-002', name: 'Pulumi Access Token', regex: /pul-[A-Za-z0-9]{40}/, severity: 'high' },

  // ── Terraform Cloud (FG-SEC-002) ──────────────────────────────────
  { id: 'terraform-cloud-token', ruleId: 'FG-SEC-002', name: 'Terraform Cloud Token', regex: /(?:TFE_TOKEN|terraform_cloud_token)\s*[:=]\s*['"]?[A-Za-z0-9.]{14,}['"]?/, severity: 'high' },

  // ── Contentful (FG-SEC-002) ───────────────────────────────────────
  { id: 'contentful-delivery-token', ruleId: 'FG-SEC-002', name: 'Contentful Delivery Token', regex: /(?:contentful_delivery|CONTENTFUL_DELIVERY_TOKEN|CONTENTFUL_ACCESS_TOKEN)\s*[:=]\s*['"]?[A-Za-z0-9_-]{43,}['"]?/, severity: 'high' },

  // ── Airtable (FG-SEC-002) ─────────────────────────────────────────
  { id: 'airtable-api-key', ruleId: 'FG-SEC-002', name: 'Airtable API Key', regex: /pat[A-Za-z0-9]{14}\.[0-9a-f]{64}/, severity: 'high' },

  // ── Notion (FG-SEC-002) ───────────────────────────────────────────
  { id: 'notion-integration-token', ruleId: 'FG-SEC-002', name: 'Notion Integration Token', regex: /(?:ntn_|secret_)[A-Za-z0-9]{43,}/, severity: 'high' },

  // ── Hugging Face (FG-SEC-002) ─────────────────────────────────────
  { id: 'huggingface-token', ruleId: 'FG-SEC-002', name: 'Hugging Face Token', regex: /hf_[A-Za-z0-9]{34,}/, severity: 'high' },

  // ── Pinecone (FG-SEC-002) ─────────────────────────────────────────
  { id: 'pinecone-api-key', ruleId: 'FG-SEC-002', name: 'Pinecone API Key', regex: /(?:pinecone_api_key|PINECONE_API_KEY)\s*[:=]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]?/, severity: 'high' },

  // ── Replicate (FG-SEC-002) ────────────────────────────────────────
  { id: 'replicate-api-token', ruleId: 'FG-SEC-002', name: 'Replicate API Token', regex: /r8_[A-Za-z0-9]{38}/, severity: 'high' },

  // ── Cohere (FG-SEC-002) ───────────────────────────────────────────
  { id: 'cohere-api-key', ruleId: 'FG-SEC-002', name: 'Cohere API Key', regex: /(?:cohere_api_key|COHERE_API_KEY|CO_API_KEY)\s*[:=]\s*['"]?[A-Za-z0-9]{40}['"]?/, severity: 'high' },

  // ── Mistral (FG-SEC-002) ──────────────────────────────────────────
  { id: 'mistral-api-key', ruleId: 'FG-SEC-002', name: 'Mistral API Key', regex: /(?:mistral_api_key|MISTRAL_API_KEY)\s*[:=]\s*['"]?[A-Za-z0-9]{32}['"]?/, severity: 'high' },

  // ── Groq (FG-SEC-002) ─────────────────────────────────────────────
  { id: 'groq-api-key', ruleId: 'FG-SEC-002', name: 'Groq API Key', regex: /gsk_[A-Za-z0-9]{48,}/, severity: 'high' },
];
