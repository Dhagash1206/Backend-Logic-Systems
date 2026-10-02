import test from "node:test";
import assert from "node:assert/strict";
import { getTtlRule, cacheKeyFor, isCacheable } from "../src/index.js";

test("fingerprinted assets get 1 year and immutable", () => {
  const rule = getTtlRule("/static/app.a1b2c3d4.js");
  assert.equal(rule.ttl, 31536000);
  assert.equal(rule.immutable, true);
});

test("html gets short TTL, unknown paths get default", () => {
  assert.equal(getTtlRule("/index.html").ttl, 120);
  assert.equal(getTtlRule("/api/data", 300).ttl, 300);
});

test("tracking params are stripped and params sorted", () => {
  const key = cacheKeyFor("https://x.com/a?b=2&utm_source=t&a=1&fbclid=z");
  assert.equal(key.url, "https://x.com/a?a=1&b=2");
});

test("responses with Set-Cookie or private are not cacheable", () => {
  assert.equal(isCacheable(new Response("ok", { headers: { "Set-Cookie": "s=1" } })), false);
  assert.equal(isCacheable(new Response("ok", { headers: { "Cache-Control": "private" } })), false);
  assert.equal(isCacheable(new Response("ok")), true);
});