import { sha256Hex } from "../_shared/crypto.js";
import { parseCookies, jsonResponse, plainResponse, nowSeconds, SESSION_COOKIE } from "../_shared/cookies.js";

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "GET") {
    const res = plainResponse(405, "Method Not Allowed");
    res.headers.set("Allow", "GET");
    return res;
  }

  const sessionId = parseCookies(request)[SESSION_COOKIE];
  if (!sessionId || !env.DB) return jsonResponse(401, { error: "unauthorized" });

  const idHash = await sha256Hex(sessionId);
  const session = await env.DB.prepare(
    "SELECT email, display_name FROM sessions WHERE id_hash = ? AND expires_at > ?"
  )
    .bind(idHash, nowSeconds())
    .first();
  if (!session) return jsonResponse(401, { error: "unauthorized" });

  return jsonResponse(200, { email: session.email, displayName: session.display_name });
}
