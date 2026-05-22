const jwt = require('jsonwebtoken');
const crypto = require('crypto');


 //JWT Service - Handles token generation, validation, and refresh logic
 
class JWTService {
    constructor() {
        this.accessTokenSecret = process.env.JWT_ACCESS_SECRET || 'access-secret-key';
        this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET || 'refresh-secret-key';
        this.accessTokenExpiry = process.env.JWT_ACCESS_EXPIRY || '45m';
        this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRY || '5d';
    }


    generateTokenPair(payload) {
        try {
            const accessToken = jwt.sign(payload, this.accessTokenSecret, {
                expiresIn: this.accessTokenExpiry,
                algorithm: 'HS256',
                jti: crypto.randomBytes(16).toString('hex'), // Unique token ID
                issuer: 'auth-service',
                audience: 'api',
            });

            const refreshToken = jwt.sign(
                { ...payload, type: 'refresh' },
                this.refreshTokenSecret,
                {
                    expiresIn: this.refreshTokenExpiry,
                    algorithm: 'HS256',
                    jti: crypto.randomBytes(16).toString('hex'),
                    issuer: 'auth-service',
                    audience: 'api',
                }
            );

            return { accessToken, refreshToken };
        } catch (error) {
            throw new Error(`Token generation failed: ${error.message}`);
        }
    }


    verifyAccessToken(token) {
        try {
            return jwt.verify(token, this.accessTokenSecret, {
                algorithms: ['HS256'],
                issuer: 'auth-service',
                audience: 'api',
            });
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                throw new Error('Access token expired');
            }
            throw new Error(`Invalid access token: ${error.message}`);
        }
    }


    verifyRefreshToken(token) {
        try {
            const decoded = jwt.verify(token, this.refreshTokenSecret, {
                algorithms: ['HS256'],
                issuer: 'auth-service',
                audience: 'api',
            });

            if (decoded.type !== 'refresh') {
                throw new Error('Invalid token type');
            }

            return decoded;
        } catch (error) {
            throw new Error(`Invalid refresh token: ${error.message}`);
        }
    }


    decodeToken(token) {
        return jwt.decode(token);
    }
}

module.exports = new JWTService();