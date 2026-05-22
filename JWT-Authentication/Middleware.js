// JWT Token verification || handle invalid token

const jwtService = require('./jwt.service');

const authMiddleware = (req, res, next) => {
  try {

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Missing or invalid authorization header',
        code: 'AUTH_MISSING',
      });
    }

    const token = authHeader.substring(7);

    const decoded = jwtService.verifyAccessToken(token);

    req.user = decoded;
    next();
  } catch (error) {
    const statusCode = error.message.includes('expired') ? 401 : 403;
    return res.status(statusCode).json({
      success: false,
      message: error.message,
      code: 'Invalid',
    });
  }
};


const refreshMiddleware = (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token required in request body',
        code: 'Refresh_Missing',
      });
    }

    const decoded = jwtService.verifyRefreshToken(refreshToken);

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message: error.message,
      code: 'Invalid',
    });
  }
};


const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'User not authenticated',
        code: 'AUTH_REQUIRED',
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions',
        code: 'AUTH_FORBIDDEN',
      });
    }

    next();
  };
};

const optionalAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      req.user = jwtService.verifyAccessToken(token);
    }
  } catch (error) {
    req.user = null;
  }
  next();
};

module.exports = {
  authMiddleware,
  refreshMiddleware,
  authorize,
  optionalAuth,
};