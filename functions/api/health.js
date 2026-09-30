import { jsonResponse, plainResponse } from "../_shared/cookies.js";

export function onRequest(context) {
  if (context.request.method !== "GET") {
    const res = plainResponse(405, "Method Not Allowed");
    res.headers.set("Allow", "GET");
    return res;
  }
  return jsonResponse(200, { status: "ok" });
}
