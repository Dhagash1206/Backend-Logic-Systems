'use strict';

class MemoryTokenStore { // dev/tests only (single process)
  constructor() {
    this._m = new Map();
    this._timer = setInterval(() => this._sweep(), 60_000);
    this._timer.unref();
  }
  _set(key, value, ttlSec) { this._m.set(key, { value, exp: Date.now() + ttlSec * 1000 }); }
  _get(key) {
    const e = this._m.get(key);
    if (!e) return undefined;
    if (e.exp <= Date.now()) { this._m.delete(key); return undefined; }
    return e.value;
  }
  _sweep() { const now = Date.now(); for (const [k, e] of this._m) if (e.exp <= now) this._m.delete(k); }
  async saveRefresh(jti, ttlSec) { this._set(`rt:${jti}`, 1, ttlSec); }
  async consumeRefresh(jti) {
    const had = this._get(`rt:${jti}`) !== undefined;
    this._m.delete(`rt:${jti}`);
    return had;
  }
  async revokeFamily(fam, ttlSec) { this._set(`rf:${fam}`, 1, ttlSec); }
  async isFamilyRevoked(fam) { return this._get(`rf:${fam}`) !== undefined; }
  async revokeUserBefore(userId, tsSec, ttlSec) { this._set(`ru:${userId}`, tsSec, ttlSec); }
  async getUserRevokedBefore(userId) { return this._get(`ru:${userId}`) || 0; }
}

class RedisTokenStore { // production; pass an ioredis client
  constructor(client, prefix = 'jwt:') { this.r = client; this.p = prefix; }
  async saveRefresh(jti, ttlSec) { await this.r.set(`${this.p}rt:${jti}`, '1', 'EX', Math.max(1, ttlSec)); }
  async consumeRefresh(jti) { return (await this.r.del(`${this.p}rt:${jti}`)) === 1; } // atomic
  async revokeFamily(fam, ttlSec) { await this.r.set(`${this.p}rf:${fam}`, '1', 'EX', Math.max(1, ttlSec)); }
  async isFamilyRevoked(fam) { return (await this.r.exists(`${this.p}rf:${fam}`)) === 1; }
  async revokeUserBefore(userId, tsSec, ttlSec) {
    await this.r.set(`${this.p}ru:${userId}`, String(tsSec), 'EX', Math.max(1, ttlSec));
  }
  async getUserRevokedBefore(userId) { return Number(await this.r.get(`${this.p}ru:${userId}`)) || 0; }
}

module.exports = { MemoryTokenStore, RedisTokenStore };