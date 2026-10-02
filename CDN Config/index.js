// Cloudflare Worker: hardened edge cache in front of an origin.
// Config comes from wrangler.toml [vars]: ORIGIN_URL, ORIGIN_TIMEOUT_MS, DEFAULT_TTL.

const TTL_RULES = [
  // Fingerprinted assets (app.a1b2c3d4.js): cache for 1 year
  { test: /\.[0-9a-f]{8,}\.(js|css|woff2?|png|jpe?g|webp|avif|svg)$/i, ttl: 31536000, immutable: true },
  { test: /\.(png|jpe?g|gif|webp|avif|svg|ico)$/i, ttl: 86400 },
  { test: /\.(js|css|woff2?)$/i, ttl: 3600 },
  { test: /(\.html?|\/)$/i, ttl: 120 },
];

const TRACKING_PARAMS = ["fbclid", "gclid", "mc_cid", "mc_eid"];

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

export function getTtlRule(pathname, defaultTtl = 300) {
  return TTL_RULES.find((r) => r.test.test(pathname)) ?? { ttl: defaultTtl };
}

// Normalize the cache key so tracking params do not fragment the cache
export function cacheKeyFor(rawUrl) {
  const url = new URL(rawUrl);
  for (const key of [...url.searchParams.keys()]) {
    if (key.startsWith("utm_") || TRACKING_PARAMS.includes(key)) {
      url.searchParams.delete(key);
    }
  }
  url.searchParams.sort();
  return new Request(url.toString(), { method: "GET" });
}

export function isCacheable(response) {
  if (response.status !== 200) return false;
  if (response.headers.has("Set-Cookie")) return false; // never cache user-specific data
  const cc = response.headers.get("Cache-Control") ?? "";
  return !/\b(private|no-store|no-cache)\b/i.test(cc);
}

// Timeout per attempt, one retry on network error or 5xx
async function fetchOrigin(request, originUrl, timeoutMs) {
  const incoming = new URL(request.url);
  const target = new URL(incoming.pathname + incoming.search, originUrl);

  for (let attempt = 0; attempt < 2; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(new Request(target, request), { signal: controller.signal });
      if (res.status < 500 || attempt === 1) return res;
    } catch (err) {
      if (attempt === 1) throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}

function finalize(response, cacheStatus) {
  const out = new Response(response.body, response);
  out.headers.set("X-Cache", cacheStatus);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  return out;
}

function log(request, status, cacheStatus, start) {
  console.log(
    JSON.stringify({
      path: new URL(request.url).pathname,
      status,
      cache: cacheStatus,
      ms: Date.now() - start,
    })
  );
}

export default {
  async fetch(request, env, ctx) {
    const start = Date.now();

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
    }
    if (!env.ORIGIN_URL) return new Response("Server misconfigured", { status: 500 });

    const timeoutMs = Number(env.ORIGIN_TIMEOUT_MS) || 5000;
    const defaultTtl = Number(env.DEFAULT_TTL) || 300;

    // Authenticated and range requests go straight to origin
    const bypass = request.headers.has("Authorization") || request.headers.has("Range");
    const cache = caches.default;
    const cacheKey = cacheKeyFor(request.url);

    try {
      if (!bypass) {
        const cached = await cache.match(cacheKey);
        if (cached) {
          log(request, cached.status, "HIT", start);
          return finalize(cached, "HIT");
        }
      }

      const originResponse = await fetchOrigin(request, env.ORIGIN_URL, timeoutMs);

      if (bypass || !isCacheable(originResponse)) {
        log(request, originResponse.status, "BYPASS", start);
        return finalize(originResponse, "BYPASS");
      }

      const { ttl, immutable } = getTtlRule(new URL(request.url).pathname, defaultTtl);
      const response = new Response(originResponse.body, originResponse);
      response.headers.set(
        "Cache-Control",
        `public, max-age=${ttl}, stale-while-revalidate=${Math.min(ttl, 86400)}${immutable ? ", immutable" : ""}`
      );

      ctx.waitUntil(cache.put(cacheKey, response.clone()));
      log(request, response.status, "MISS", start);
      return finalize(response, "MISS");
    } catch (err) {
      console.error(JSON.stringify({ error: String(err), path: new URL(request.url).pathname }));
      const status = err?.name === "AbortError" ? 504 : 502;
      return new Response(status === 504 ? "Gateway Timeout" : "Bad Gateway", { status });
    }
  },
};