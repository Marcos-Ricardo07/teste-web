import { sha256Hex } from "../_shared/crypto.js";
import { parseCookies, expiredCookie, plainResponse, SESSION_COOKIE } from "../_shared/cookies.js";
import { baseUrl } from "../_shared/providers.js";

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    const res = plainResponse(405, "Method Not Allowed");
    res.headers.set("Allow", "POST");
    return res;
  }

  const base = baseUrl(env);
  if (!base || request.headers.get("Origin") !== base) return plainResponse(403, "Forbidden");

  const sessionId = parseCookies(request)[SESSION_COOKIE];
  if (sessionId && env.DB) {
    const idHash = await sha256Hex(sessionId);
    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(idHash).run();
  }

  const headers = new Headers({ Location: `${base}/`, "Cache-Control": "no-store" });
  headers.append("Set-Cookie", expiredCookie(SESSION_COOKIE, "Strict"));
  return new Response(null, { status: 302, headers });
}
