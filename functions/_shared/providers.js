const PROVIDERS = {
  google: {
    issuer: "https://accounts.google.com",
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
    scope: "openid email profile",
    usesNonce: true,
    clientIdVar: "GOOGLE_CLIENT_ID",
    clientSecretVar: "GOOGLE_CLIENT_SECRET",
  },
  github: {
    issuer: "https://github.com",
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    userUrl: "https://api.github.com/user",
    scope: null,
    usesNonce: false,
    clientIdVar: "GITHUB_CLIENT_ID",
    clientSecretVar: "GITHUB_CLIENT_SECRET",
  },
};

// Returns a fresh config object per call, or null for unknown providers.
export function getProvider(name, env) {
  if (!Object.prototype.hasOwnProperty.call(PROVIDERS, name)) return null;
  const p = PROVIDERS[name];
  return {
    ...p,
    name,
    clientId: env[p.clientIdVar],
    clientSecret: env[p.clientSecretVar],
  };
}

export function redirectUri(env, providerName) {
  return `${baseUrl(env)}/oauth/callback/${providerName}`;
}

export function baseUrl(env) {
  return String(env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
}
