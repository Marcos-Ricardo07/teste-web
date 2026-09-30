import { randomToken, sha256Hex, timingSafeEqual, openWithSecret, base64UrlDecode } from "../../_shared/crypto.js";
import {
  parseCookies,
  expiredCookie,
  nowSeconds,
  OAUTH_TX_COOKIE,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
} from "../../_shared/cookies.js";
import { getProvider, redirectUri, baseUrl } from "../../_shared/providers.js";

const GITHUB_API_VERSION = "2026-03-10";
const USER_AGENT = "pages-oauth";

// Errors are generic on purpose: no provider/token details reach the browser or logs.
function fail(status, message) {
  const headers = new Headers({ "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  headers.append("Set-Cookie", expiredCookie(OAUTH_TX_COOKIE));
  return new Response(message, { status, headers });
}

export async function onRequest(context) {
  const { request, env, params } = context;

  const provider = getProvider(String(params.provider || ""), env);
  if (!provider) return fail(404, "Not Found");

  if (request.method !== "GET") {
    const res = fail(405, "Method Not Allowed");
    res.headers.set("Allow", "GET");
    return res;
  }

  if (!provider.clientId || !provider.clientSecret || !env.PUBLIC_BASE_URL || !env.DB) {
    return fail(500, "Server misconfigured");
  }

  // 1. Provider error or missing parameters.
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (url.searchParams.has("error") || !code || !state) return fail(400, "Bad Request");

  // 2. Transaction cookie.
  const txId = parseCookies(request)[OAUTH_TX_COOKIE];
  if (!txId) return fail(400, "Bad Request");

  // 3. Unexpired transaction for this provider.
  const txHash = await sha256Hex(txId);
  const tx = await env.DB.prepare(
    "SELECT state_hash, nonce, code_verifier FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?"
  )
    .bind(txHash, provider.name, nowSeconds())
    .first();
  if (!tx) return fail(400, "Bad Request");

  // 4. State must match.
  const stateHash = await sha256Hex(state);
  if (!timingSafeEqual(stateHash, tx.state_hash)) return fail(400, "Bad Request");

  // 5. Single use: delete before doing anything else. If a concurrent request already
  //    consumed it, stop here.
  const del = await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(txHash).run();
  if (!del.meta || del.meta.changes !== 1) return fail(400, "Bad Request");

  let codeVerifier;
  try {
    codeVerifier = await openWithSecret(tx.code_verifier, txId, "pkce");
  } catch {
    return fail(400, "Bad Request");
  }

  // 6. Code exchange (POST body only).
  let tokens;
  try {
    const tokenRes = await fetch(provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
      body: new URLSearchParams({
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        code,
        redirect_uri: redirectUri(env, provider.name),
        grant_type: "authorization_code",
        code_verifier: codeVerifier,
      }),
    });
    if (!tokenRes.ok) return fail(502, "Login failed");
    tokens = await tokenRes.json();
  } catch {
    return fail(502, "Login failed");
  }

  // 7. Identity.
  let identity;
  try {
    identity =
      provider.name === "google"
        ? await verifyGoogleIdToken(tokens.id_token, provider.clientId, tx.nonce)
        : await fetchAndRevokeGitHubIdentity(tokens, provider);
  } catch {
    identity = null;
  }
  if (!identity) return fail(401, "Login failed");

  // 8. Session.
  const sessionId = randomToken();
  const sessionHash = await sha256Hex(sessionId);
  const now = nowSeconds();
  await env.DB.prepare(
    "INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(sessionHash, identity.issuer, identity.subject, identity.email, identity.displayName, now + SESSION_TTL_SECONDS, now)
    .run();

  // 9 + 10. Session cookie, clear transaction cookie, redirect home.
  const headers = new Headers({ Location: `${baseUrl(env)}/`, "Cache-Control": "no-store" });
  headers.append(
    "Set-Cookie",
    `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`
  );
  headers.append("Set-Cookie", expiredCookie(OAUTH_TX_COOKIE));
  return new Response(null, { status: 302, headers });
}

function decodeJsonSegment(segment) {
  return JSON.parse(new TextDecoder().decode(base64UrlDecode(segment)));
}

async function verifyGoogleIdToken(idToken, clientId, expectedNonce) {
  if (typeof idToken !== "string") return null;
  const parts = idToken.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;

  const header = decodeJsonSegment(headerB64);
  if (header.alg !== "RS256" || typeof header.kid !== "string") return null;

  const discoveryRes = await fetch("https://accounts.google.com/.well-known/openid-configuration");
  if (!discoveryRes.ok) return null;
  const discovery = await discoveryRes.json();
  if (typeof discovery.jwks_uri !== "string" || !discovery.jwks_uri.startsWith("https://")) return null;

  const jwksRes = await fetch(discovery.jwks_uri);
  if (!jwksRes.ok) return null;
  const jwks = await jwksRes.json();
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) return null;

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64UrlDecode(signatureB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  );
  if (!valid) return null;

  // Only now is the payload trustworthy enough to inspect.
  const claims = decodeJsonSegment(payloadB64);
  if (claims.iss !== "https://accounts.google.com" && claims.iss !== "accounts.google.com") return null;

  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) return null;
  if (aud.length > 1 && claims.azp !== clientId) return null;

  if (typeof claims.exp !== "number" || claims.exp <= nowSeconds()) return null;
  if (!expectedNonce || typeof claims.nonce !== "string" || !timingSafeEqual(claims.nonce, expectedNonce)) return null;
  if (typeof claims.sub !== "string" || !claims.sub) return null;

  return {
    issuer: "https://accounts.google.com",
    subject: claims.sub,
    email: claims.email_verified === true && typeof claims.email === "string" ? claims.email : null,
    displayName: typeof claims.name === "string" ? claims.name : null,
  };
}

async function fetchAndRevokeGitHubIdentity(tokens, provider) {
  const accessToken = tokens && tokens.access_token;
  if (typeof accessToken !== "string" || !accessToken) return null;
  if (String(tokens.token_type || "").toLowerCase() !== "bearer") return null;

  const userRes = await fetch(provider.userUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      "User-Agent": USER_AGENT,
    },
  });
  if (userRes.status !== 200) return null;
  const user = await userRes.json();
  if (typeof user.id !== "number") return null;

  // Revoke the grant so the token does not outlive the login.
  const basic = btoa(`${provider.clientId}:${provider.clientSecret}`);
  const revokeRes = await fetch(`https://api.github.com/applications/${encodeURIComponent(provider.clientId)}/grant`, {
    method: "DELETE",
    headers: {
      Authorization: `Basic ${basic}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      "User-Agent": USER_AGENT,
    },
    body: JSON.stringify({ access_token: accessToken }),
  });
  if (revokeRes.status !== 204) return null;

  return {
    issuer: provider.issuer,
    subject: String(user.id),
    email: typeof user.email === "string" ? user.email : null,
    displayName: typeof user.name === "string" && user.name ? user.name : typeof user.login === "string" ? user.login : null,
  };
}
