/**
 * JS Wrapper Entry Point for Warden Worker
 *
 * Routes CPU-heavy endpoints to a Rust Durable Object (HEAVY_DO) which has
 * a much higher CPU budget than regular Workers, preventing CPU time limit errors.
 *
 * Offloaded routes (per TODO.md):
 *   GET  /api/config
 *   GET  /api/sync
 *   *    /api/two-factor*
 *   *    /api/webauthn*
 *
 * All other requests pass through to the Rust WASM module directly.
 */

import RustWorker from "../build/index.js";

function normalizePathname(pathname) {
  if (typeof pathname !== "string") return "/";
  if (pathname === "/") return "/";
  return pathname.replace(/\/+$/, "");
}

// Routes to offload to HEAVY_DO. Prefix-matched for wildcard routes.
const HEAVY_DO_PREFIXES = [
  "/api/config",
  "/api/sync",
  "/api/two-factor",
  "/api/webauthn",
];

function shouldOffloadToHeavyDo(pathname) {
  for (const prefix of HEAVY_DO_PREFIXES) {
    if (pathname === prefix || pathname.startsWith(prefix + "/")) {
      return true;
    }
  }
  return false;
}

// Shard DO instances by user id from JWT sub (decoded without verification).
// The DO handler performs full JWT verification — this is only for sharding.
function getBearerToken(request) {
  const auth = request.headers.get("Authorization") || request.headers.get("authorization");
  if (!auth) return null;
  const m = auth.match(/^\s*Bearer\s+(.+?)\s*$/i);
  return m ? m[1] : null;
}

function decodeJwtSubUnsafe(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const pad = parts[1].length % 4;
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/") + (pad ? "=".repeat(4 - pad) : "");
    const json = atob(b64);
    return JSON.parse(json)?.sub ?? null;
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    request = new Request(url.toString(), request);

    // Route CPU-heavy endpoints to Durable Object when binding is present.
    if (env.HEAVY_DO && shouldOffloadToHeavyDo(url.pathname)) {
      const token = getBearerToken(request);
      const sub = token ? decodeJwtSubUnsafe(token) : null;
      const name = sub ? `user:${sub}` : "user:default";
      const id = env.HEAVY_DO.idFromName(name);
      const stub = env.HEAVY_DO.get(id);
      return stub.fetch(request);
    }

    // All other requests go to the Rust WASM module.
    const worker = new RustWorker(ctx, env);
    return worker.fetch(request);
  },

  async scheduled(event, env, ctx) {
    const worker = new RustWorker(ctx, env);
    return worker.scheduled(event);
  },
};

// Re-export Rust Durable Object classes from WASM build.
// wrangler.jsonc binds HEAVY_DO -> class_name = "HeavyDo".
export { HeavyDo, NotificationsHub } from "../build/index.js";
