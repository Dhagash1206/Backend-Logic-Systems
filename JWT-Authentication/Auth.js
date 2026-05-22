const jwtService = require('./jwt.service');
const crypto = require('crypto');

// token refresh, and logout flows
//Handles authentication endpoints


class AuthController {

  async login(req, res, userModel) {
    try {
      const { email, password } = req.body;

      // Validate input
      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: 'Email and password are required',
          code: 'INVALID_INPUT',
        });
      }

      const user = await userModel.findOne({ email });
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password',
          code: 'AUTH_FAILED',
        });
      }

      const isPasswordValid = password === user.password;

      if (!isPasswordValid) {
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password',
          code: 'AUTH_FAILED',
        });
      }

      const tokenPayload = {
        id: user._id || user.id,
        email: user.email,
        role: user.role || 'user',
      };

      const { accessToken, refreshToken } = jwtService.generateTokenPair(tokenPayload);

      res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
          accessToken,
          refreshToken,
          user: {
            id: user.id || user._id,
            email: user.email,
            role: user.role || 'user',
          },
        },
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Login failed',
        code: 'LOGIN_ERROR',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }


  refreshAccessToken(req, res) {
    try {
      const { id, email, role } = req.user;

      const tokenPayload = { id, email, role };
      const { accessToken } = jwtService.generateTokenPair(tokenPayload);

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken,
        },
      });
    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(500).json({
        success: false,
        message: 'Token refresh failed',
        code: 'REFRESH_ERROR',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }

  async logout(req, res, refreshTokenModel) {
    try {
      const { id } = req.user;


      res.status(200).json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed',
        code: 'LOGOUT_ERROR',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }


  getCurrentUser(req, res) {
    try {
      const user = req.user;

      res.status(200).json({
        success: true,
        data: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Failed to fetch user',
        code: 'USER_FETCH_ERROR',
      });
    }
  }
}

module.exports = new AuthController();
