export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const cookies = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    if (!name || name in cookies) continue;
    cookies[name] = part.slice(idx + 1).trim();
  }
  return cookies;
}

export const OAUTH_TX_COOKIE = "__Host-oauth-tx";
export const SESSION_COOKIE = "__Host-session";
export const SESSION_TTL_SECONDS = 28800;
export const OAUTH_TX_TTL_SECONDS = 600;

export function expiredCookie(name, sameSite = "Lax") {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`;
}

export function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// Error/session responses: never cached.
export function plainResponse(status, body = "") {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export function jsonResponse(status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
