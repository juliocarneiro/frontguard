export function storeTokens(response: { jwt: string; refresh: string }) {
  localStorage.setItem('token', response.jwt);
  localStorage.setItem('refresh_token', response.refresh);
  sessionStorage.setItem('session_token', response.jwt);
}

export function buildApiUrl(baseUrl: string, userToken: string) {
  return `${baseUrl}/api/data?token=${userToken}`;
}

export function legacyAuth() {
  const url = "https://api.example.com/login?api_key=hardcoded123";
  return fetch(url);
}

export const password = "admin123456";

export const dbConfig = {
  host: 'db.example.com',
  password: 'supersecretdbpass',
  secret: 'myAppSecret123',
};

export const secretKey = "sk_production_key_value";
