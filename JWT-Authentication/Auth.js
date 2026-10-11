'use strict';
// userModel needs: findOne({ email }), findById(id); user fields: id|_id, email,
// password (bcrypt hash), role, isActive (optional).
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwtService = require('./Service');
const { AuthError } = require('./Service');
const { extractRefreshToken } = require('./Middleware');
const cfg = require('./config');

const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), cfg.bcryptRounds);
const MAX_BCRYPT_BYTES = 72;
const userId = (u) => String(u.id !== undefined ? u.id : u._id);

function send(res, status, body) {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
  return res.status(status).json(body);
}
const fail = (res, status, code, message) => send(res, status, { success: false, message, code });

function setRefreshCookie(res, token, expSec) {
  const c = cfg.refresh.cookie;
  res.cookie(c.name, token, {
    httpOnly: true, secure: c.secure, sameSite: c.sameSite,
    path: c.path, domain: c.domain, expires: new Date(expSec * 1000),
  });
}

function clearRefreshCookie(res) {
  const c = cfg.refresh.cookie;
  res.clearCookie(c.name, { httpOnly: true, secure: c.secure, sameSite: c.sameSite, path: c.path, domain: c.domain });
}

function tokenResponse(res, pair, extra = {}) {
  const data = { accessToken: pair.accessToken, expiresIn: pair.accessExpiresIn, ...extra };
  if (cfg.refresh.transport === 'cookie') setRefreshCookie(res, pair.refreshToken, pair.refreshExpiresAt);
  else data.refreshToken = pair.refreshToken;
  return data;
}

function internalError(res, err, code, message) {
  jwtService.logger.error(`[auth] ${code}:`, err.message);
  return fail(res, 500, code, message);
}

class AuthController {
  hashPassword(plain) {
    if (typeof plain !== 'string' || plain.length < 8 || Buffer.byteLength(plain) > MAX_BCRYPT_BYTES) {
      throw new Error('Password must be 8-72 bytes');
    }
    return bcrypt.hash(plain, cfg.bcryptRounds);
  }

  async login(req, res, userModel) {
    try {
      const { email, password } = req.body || {};
      if (typeof email !== 'string' || typeof password !== 'string' || !email || !password ||
          email.length > 254 || Buffer.byteLength(password) > MAX_BCRYPT_BYTES) {
        return fail(res, 400, 'INVALID_INPUT', 'Email and password are required');
      }

      const user = await userModel.findOne({ email: email.trim().toLowerCase() });
      const hash = user && typeof user.password === 'string' ? user.password : DUMMY_HASH;
      const passwordOk = await bcrypt.compare(password, hash);

      if (!user || !passwordOk || user.isActive === false) {
        return fail(res, 401, 'AUTH_FAILED', 'Invalid email or password');
      }

      const pair = await jwtService.issueSession({ id: userId(user), role: user.role || 'user' });
      return send(res, 200, {
        success: true,
        message: 'Login successful',
        data: tokenResponse(res, pair, { user: { id: userId(user), email: user.email, role: user.role || 'user' } }),
      });
    } catch (err) {
      return internalError(res, err, 'LOGIN_ERROR', 'Login failed');
    }
  }

  async refresh(req, res, userModel) { // mount after refreshMiddleware
    try {
      const pair = await jwtService.rotateRefreshToken(req.refreshToken, async (id) => {
        const user = await userModel.findById(id);
        if (!user || user.isActive === false) return null;
        return { id: userId(user), role: user.role || 'user' };
      });
      return send(res, 200, { success: true, message: 'Token refreshed successfully', data: tokenResponse(res, pair) });
    } catch (err) {
      if (err instanceof AuthError) {
        clearRefreshCookie(res);
        return fail(res, 401, 'REFRESH_INVALID', 'Session expired, please log in again');
      }
      return internalError(res, err, 'REFRESH_ERROR', 'Token refresh failed');
    }
  }

  async logout(req, res) { // mount with optionalAuth
    try {
      const refreshToken = extractRefreshToken(req);
      if (refreshToken) await jwtService.revokeSessionByRefreshToken(refreshToken);
      if (req.user && req.user.sid) await jwtService.revokeFamily(req.user.sid);
      clearRefreshCookie(res);
      return send(res, 200, { success: true, message: 'Logout successful' });
    } catch (err) {
      return internalError(res, err, 'LOGOUT_ERROR', 'Logout failed');
    }
  }

  async logoutAll(req, res) { // mount with authMiddleware
    try {
      await jwtService.revokeAllForUser(req.user.id);
      clearRefreshCookie(res);
      return send(res, 200, { success: true, message: 'Logged out of all sessions' });
    } catch (err) {
      return internalError(res, err, 'LOGOUT_ALL_ERROR', 'Logout failed');
    }
  }

  async getCurrentUser(req, res, userModel) {
    try {
      const user = await userModel.findById(req.user.id);
      if (!user || user.isActive === false) return fail(res, 404, 'USER_NOT_FOUND', 'User not found');
      return send(res, 200, { success: true, data: { id: userId(user), email: user.email, role: user.role || 'user' } });
    } catch (err) {
      return internalError(res, err, 'USER_FETCH_ERROR', 'Failed to fetch user');
    }
  }
}

module.exports = new AuthController();