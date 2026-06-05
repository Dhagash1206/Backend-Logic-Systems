// Rate Limiting Module - Brute-force attack prevention with IP-based blocking
class RateLimiter {
    constructor(config = {}) {
        this.windowMs = config.windowMs || 15 * 60 * 1000;
        this.maxRequests = config.maxRequests || 100;
        this.blockDurationMs = config.blockDurationMs || 60 * 60 * 1000;
        this.cleanupIntervalMs = config.cleanupIntervalMs || 5 * 60 * 1000;

        this.requestCounts = new Map();
        this.blockedIPs = new Map();
        this.requestHistory = new Map();

        this.startCleanup();
    }

    getClientIP(req) {
        return (
            req.headers['x-forwarded-for']?.split(',')[0].trim() ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            'unknown'
        );
    }

    isIPBlocked(ip) {
        const blockExpireTime = this.blockedIPs.get(ip);
        if (!blockExpireTime) return false;

        if (Date.now() > blockExpireTime) {
            this.blockedIPs.delete(ip);
            this.requestHistory.delete(ip);
            return false;
        }
        return true;
    }

    checkLimit(ip) {
        if (this.isIPBlocked(ip)) {
            const blockExpireTime = this.blockedIPs.get(ip);
            return {
                allowed: false,
                remaining: 0,
                retryAfter: Math.ceil((blockExpireTime - Date.now()) / 1000),
                reason: 'IP blocked due to rate limit exceeded',
            };
        }

        const now = Date.now();
        const record = this.requestCounts.get(ip) || { count: 0, windowStart: now };

        if (now - record.windowStart > this.windowMs) {
            record.count = 0;
            record.windowStart = now;
        }

        record.count++;
        this.requestCounts.set(ip, record);

        if (!this.requestHistory.has(ip)) {
            this.requestHistory.set(ip, []);
        }
        this.requestHistory.get(ip).push(now);

        if (record.count > this.maxRequests) {
            this.blockedIPs.set(ip, now + this.blockDurationMs);

            return {
                allowed: false,
                remaining: 0,
                retryAfter: Math.ceil(this.blockDurationMs / 1000),
                reason: 'Rate limit exceeded. IP blocked.',
            };
        }

        const remaining = this.maxRequests - record.count;
        const windowResetTime = Math.ceil((record.windowStart + this.windowMs - now) / 1000);

        return {
            allowed: true,
            remaining,
            retryAfter: windowResetTime,
            reason: null,
        };
    }

    // Express middleware for rate limiting
    middleware() {
        return (req, res, next) => {
            const ip = this.getClientIP(req);
            const result = this.checkLimit(ip);

            res.setHeader('RateLimit', this.maxRequests);
            res.setHeader('RateLimit-Remaining', Math.max(0, result.remaining));
            res.setHeader('Retry-After', result.retryAfter);

            if (!result.allowed) {
                console.warn(`[RATE LIMIT] IP ${ip} blocked: ${result.reason}`);
                return res.status(429).json({
                    error: 'Too many requests',
                    message: result.reason,
                    retryAfter: result.retryAfter,
                });
            }

            next();
        };
    }

    blockIP(ip, durationMs = this.blockDurationMs) {
        this.blockedIPs.set(ip, Date.now() + durationMs);
        console.log(`[SECURITY] IP ${ip} manually blocked`);
    }

    unblockIP(ip) {
        this.blockedIPs.delete(ip);
        this.requestCounts.delete(ip);
        console.log(`[SECURITY] IP ${ip} unblocked`);
    }

    // Get detailed stats for an IP
    getIPStats(ip) {
        const record = this.requestCounts.get(ip);
        const isBlocked = this.isIPBlocked(ip);
        const history = this.requestHistory.get(ip) || [];

        return {
            ip,
            isBlocked,
            currentCount: record?.count || 0,
            windowStart: record?.windowStart || null,
            requestHistory: history.slice(-10),
            totalRequests: history.length,
            blockExpireTime: isBlocked ? this.blockedIPs.get(ip) : null,
        };
    }

    // Automatic cleanup of expired records
    startCleanup() {
        this.cleanupInterval = setInterval(() => {
            const now = Date.now();

            for (const [ip, expireTime] of this.blockedIPs.entries()) {
                if (now > expireTime) {
                    this.blockedIPs.delete(ip);
                    this.requestHistory.delete(ip);
                }
            }

            for (const [ip, record] of this.requestCounts.entries()) {
                if (now - record.windowStart > this.windowMs * 2) {
                    this.requestCounts.delete(ip);
                }
            }

            console.log(`[CLEANUP] Rate limiter cleanup at ${new Date().toISOString()}`);
        }, this.cleanupIntervalMs);
    }

    // Stop cleanup interval on app shutdown
    stopCleanup() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
    }

    // Get all blocked IPs
    getBlockedIPs() {
        const now = Date.now();
        const blocked = [];

        for (const [ip, expireTime] of this.blockedIPs.entries()) {
            if (now < expireTime) {
                blocked.push({
                    ip,
                    blockedAt: expireTime - this.blockDurationMs,
                    expiresAt: expireTime,
                    remainingMs: expireTime - now,
                });
            }
        }

        return blocked;
    }


}

module.exports = RateLimiter;

/* USAGE:
const express = require('express');
const RateLimiter = require('./rateLimiter');

const app = express();
const limiter = new RateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 100,
  blockDurationMs: 60 * 60 * 1000,
});

app.use(limiter.middleware());

app.get('/api/login', limiter.middleware(), (req, res) => {
  res.json({ message: 'Login endpoint' });
});

process.on('SIGTERM', () => {
  limiter.stopCleanup();
  process.exit(0);
});
*/