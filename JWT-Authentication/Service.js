'use strict';
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cfg = require('./config');

class AuthError extends Error {
  constructor(code) { super(code); this.name = 'AuthError'; this.code = code; }
}

const newId = () => crypto.randomBytes(16).toString('hex');
const nowSec = () => Math.floor(Date.now() / 1000);

class JWTService {
  init({ store, logger = console }) {
    if (!store) throw new Error('JWTService.init: a token store is required');
    this.store = store;
    this.logger = logger;
    return this;
  }

  _ready() {
    if (!this.store) throw new Error('JWTService not initialised: call jwtService.init({ store })');
  }

  _verify(token, ring, expectedType) {
    if (typeof token !== 'string' || token.length > 2048) throw new AuthError('TOKEN_INVALID');
    const decoded = jwt.decode(token, { complete: true });
    const secret = decoded && ring.byKid.get(decoded.header.kid);
    if (!secret) throw new AuthError('TOKEN_INVALID');

    let claims;
    try {
      claims = jwt.verify(token, secret, {
        algorithms: ['HS256'],
        issuer: cfg.issuer,
        audience: cfg.audience,
        clockTolerance: cfg.clockToleranceSec,
      });
    } catch (err) {
      throw new AuthError(err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID');
    }
    if (claims.type !== expectedType || !claims.sub || !claims.jti) throw new AuthError('TOKEN_INVALID');
    return claims;
  }

  async _mint(user, fam, sessionStart) {
    const sub = String(user.id);
    const now = nowSec();

    const accessToken = jwt.sign(
      { type: 'access', role: user.role, sid: fam },
      cfg.access.current.secret,
      {
        algorithm: 'HS256', keyid: cfg.access.current.kid, expiresIn: cfg.access.ttl,
        subject: sub, issuer: cfg.issuer, audience: cfg.audience, jwtid: newId(),
      }
    );

    const refreshExp = Math.min(now + cfg.refresh.ttl, sessionStart + cfg.refresh.sessionMax);
    if (refreshExp <= now) throw new AuthError('SESSION_EXPIRED');

    const refreshJti = newId();
    const refreshToken = jwt.sign(
      { type: 'refresh', fam, sst: sessionStart, exp: refreshExp },
      cfg.refresh.current.secret,
      {
        algorithm: 'HS256', keyid: cfg.refresh.current.kid,
        subject: sub, issuer: cfg.issuer, audience: cfg.audience, jwtid: refreshJti,
      }
    );
    await this.store.saveRefresh(refreshJti, refreshExp - now);

    return { accessToken, refreshToken, accessExpiresIn: cfg.access.ttl, refreshExpiresAt: refreshExp };
  }

  async issueSession(user) { // user = { id, role }
    this._ready();
    return this._mint(user, newId(), nowSec());
  }

  // loadUser(id) -> fresh { id, role } or null (account deleted/disabled)
  async rotateRefreshToken(token, loadUser) {
    this._ready();
    const c = this._verify(token, cfg.refresh, 'refresh');
    if (!c.fam || !Number.isInteger(c.sst)) throw new AuthError('TOKEN_INVALID');

    const [famRevoked, revokedBefore] = await Promise.all([
      this.store.isFamilyRevoked(c.fam),
      this.store.getUserRevokedBefore(c.sub),
    ]);
    if (famRevoked || revokedBefore >= c.iat) throw new AuthError('TOKEN_REVOKED');

    const user = await loadUser(c.sub);
    if (!user) {
      await this.revokeFamily(c.fam);
      throw new AuthError('TOKEN_REVOKED');
    }

    const consumed = await this.store.consumeRefresh(c.jti);
    if (!consumed) { // replay => assume theft, kill the session
      await this.revokeFamily(c.fam);
      this.logger.warn('[auth] refresh token reuse detected', { user: c.sub, family: c.fam });
      throw new AuthError('REFRESH_REUSED');
    }
    return this._mint(user, c.fam, c.sst);
  }

  async verifyAccessToken(token) {
    this._ready();
    const c = this._verify(token, cfg.access, 'access');
    const [famRevoked, revokedBefore] = await Promise.all([
      this.store.isFamilyRevoked(c.sid),
      this.store.getUserRevokedBefore(c.sub),
    ]);
    if (famRevoked || revokedBefore >= c.iat) throw new AuthError('TOKEN_REVOKED');
    return { id: c.sub, role: c.role, sid: c.sid, jti: c.jti, exp: c.exp };
  }

  async revokeFamily(fam) {
    this._ready();
    await this.store.revokeFamily(fam, cfg.refresh.ttl);
  }

  async revokeSessionByRefreshToken(token) {
    try {
      const c = this._verify(token, cfg.refresh, 'refresh');
      if (c.fam) await this.revokeFamily(c.fam);
    } catch (err) {
      if (!(err instanceof AuthError)) throw err;
    }
  }

  async revokeAllForUser(userId) {
    this._ready();
    await this.store.revokeUserBefore(String(userId), nowSec(), cfg.refresh.ttl + cfg.access.ttl);
  }
}

module.exports = new JWTService();
module.exports.AuthError = AuthError;
module.exports.JWTService = JWTService;