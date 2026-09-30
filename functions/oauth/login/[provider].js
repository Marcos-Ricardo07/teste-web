import { randomToken, sha256Hex, codeChallengeFromVerifier, sealWithSecret } from "../../_shared/crypto.js";
import { OAUTH_TX_COOKIE, OAUTH_TX_TTL_SECONDS, nowSeconds, plainResponse } from "../../_shared/cookies.js";
import { getProvider, redirectUri } from "../../_shared/providers.js";

export async function onRequest(context) {
  const { request, env, params } = context;

  const provider = getProvider(String(params.provider || ""), env);
  if (!provider) return plainResponse(404, "Not Found");

  if (request.method !== "GET") {
    const res = plainResponse(405, "Method Not Allowed");
    res.headers.set("Allow", "GET");
    return res;
  }

  if (!provider.clientId || !env.PUBLIC_BASE_URL || !env.DB) {
    return plainResponse(500, "Server misconfigured");
  }

  const txId = randomToken();
  const state = randomToken();
  const codeVerifier = randomToken();
  const codeChallenge = await codeChallengeFromVerifier(codeVerifier);
  const nonce = provider.usesNonce ? randomToken() : null;

  const [txHash, stateHash, sealedVerifier] = await Promise.all([
    sha256Hex(txId),
    sha256Hex(state),
    sealWithSecret(codeVerifier, txId, "pkce"),
  ]);

  await env.DB.prepare(
    "INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(txHash, provider.name, stateHash, nonce, sealedVerifier, nowSeconds() + OAUTH_TX_TTL_SECONDS)
    .run();

  const authUrl = new URL(provider.authorizeUrl);
  authUrl.searchParams.set("client_id", provider.clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri(env, provider.name));
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  if (provider.scope) authUrl.searchParams.set("scope", provider.scope);
  if (nonce) authUrl.searchParams.set("nonce", nonce);

  const headers = new Headers({
    Location: authUrl.toString(),
    "Cache-Control": "no-store",
  });
  headers.append(
    "Set-Cookie",
    `${OAUTH_TX_COOKIE}=${txId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${OAUTH_TX_TTL_SECONDS}`
  );
  return new Response(null, { status: 302, headers });
}
