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
  "/identity/accounts/prelogin",
  "/api/accounts/prelogin",
  "/identity/accounts/webauthn/assertion-options",
  "/accounts/webauthn/assertion-options",
  "/api/two-factor",
  "/api/webauthn",
  "/notifications",
  "/api/auth-requests",
  "/identity/connect/token",
  "/api/devices/knowndevice",
];

const ICON_CACHE_TTL_SECONDS = 604800;
const ICON_NEGATIVE_CACHE_TTL_SECONDS = 300;
const ICON_TRANSIENT_ERROR_TTL_SECONDS = 30;
const DEFAULT_ICON_PATH = "/images/bwi-globe.png";

function extractIconDomain(pathname) {
  if (!pathname.startsWith("/icons/")) {
    return null;
  }

  const rawPath = pathname.slice("/icons/".length);
  if (!rawPath) {
    return null;
  }

  const noSuffix = rawPath.endsWith("/icon.png")
    ? rawPath.slice(0, -"/icon.png".length)
    : rawPath;
  const domain = noSuffix.trim().toLowerCase();

  if (!domain || domain.includes("/") || domain.length > 253) {
    return null;
  }

  return domain;
}

function cacheControlHeader(seconds) {
  return `public, max-age=${seconds}, immutable`;
}

async function fetchDefaultIcon(requestUrl) {
  const fallbackUrl = new URL(DEFAULT_ICON_PATH, requestUrl).toString();
  const fallback = await fetch(fallbackUrl, {
    cf: {
      cacheEverything: true,
      cacheTtl: ICON_NEGATIVE_CACHE_TTL_SECONDS,
    },
  });

  const headers = new Headers(fallback.headers);
  headers.set("cache-control", cacheControlHeader(ICON_NEGATIVE_CACHE_TTL_SECONDS));
  headers.set("x-icons-fallback", "1");

  return new Response(fallback.body, {
    status: 200,
    statusText: "OK",
    headers,
  });
}

async function proxyIconRequest(requestUrl, pathname) {
  const domain = extractIconDomain(pathname);
  if (!domain) {
    return new Response("Bad Request", { status: 400 });
  }

  const targetUrl = `https://vault.bitwarden.com/icons/${encodeURIComponent(domain)}/icon.png`;
  const upstream = await fetch(targetUrl, {
    cf: {
      cacheEverything: true,
      cacheTtl: ICON_CACHE_TTL_SECONDS,
      cacheTtlByStatus: {
        "200-299": ICON_CACHE_TTL_SECONDS,
        "404": ICON_NEGATIVE_CACHE_TTL_SECONDS,
        "500-599": ICON_TRANSIENT_ERROR_TTL_SECONDS,
      },
    },
  });

  if (upstream.status === 404 || upstream.status >= 500) {
    return fetchDefaultIcon(requestUrl);
  }

  const responseHeaders = new Headers(upstream.headers);
  responseHeaders.set("cache-control", cacheControlHeader(ICON_CACHE_TTL_SECONDS));
  responseHeaders.set("x-icons-fallback", "0");

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
}

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

function computeRequestShard(url, tokenSub) {
  if (tokenSub) {
    return `user:${tokenSub}`;
  }

  if (url.pathname === "/icons" || url.pathname.startsWith("/icons/")) {
    const host = (url.searchParams.get("hostname") || url.searchParams.get("domain") || "default").toLowerCase();
    const bucket = host.charCodeAt(0) % 16;
    return `icons-bucket:${bucket}`;
  }

  if (url.pathname === "/api/auth-requests" || url.pathname.startsWith("/api/auth-requests/")) {
    const idSeed = `${url.pathname}|${url.searchParams.get("code") || ""}`;
    const bucket = idSeed.charCodeAt(0) % 16;
    return `auth-requests-bucket:${bucket}`;
  }

  return "user:default";
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    url.pathname = normalizePathname(url.pathname);
    request = new Request(url.toString(), request);

    if (url.pathname === "/icons" || url.pathname.startsWith("/icons/")) {
      return proxyIconRequest(request.url, url.pathname);
    }

    // Route CPU-heavy endpoints to Durable Object when binding is present.
    if (env.HEAVY_DO && shouldOffloadToHeavyDo(url.pathname)) {
      const token = getBearerToken(request);
      const sub = token ? decodeJwtSubUnsafe(token) : null;
      const name = computeRequestShard(url, sub);
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
