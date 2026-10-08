const rbacService = require('./Service');

// Role listing, permission lookup and role assignment flows
// Handles RBAC management endpoints

class RBACController {

  listRoles(req, res) {
    try {
      res.status(200).json({
        success: true,
        data: { roles: rbacService.listRoles() },
      });
    } catch (error) {
      console.error('List roles error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to list roles',
        code: 'ROLE_LIST_ERROR',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }


  getMyPermissions(req, res) {
    try {
      const roles = req.user.roles || req.user.role;

      res.status(200).json({
        success: true,
        data: {
          roles: rbacService.normalizeRoles(roles),
          permissions: rbacService.getUserPermissions(roles),
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Failed to fetch permissions',
        code: 'PERMISSION_FETCH_ERROR',
      });
    }
  }


  async assignRole(req, res, userModel) {
    try {
      const { userId, role } = req.body;

      // Validate input
      if (!userId || !role) {
        return res.status(400).json({
          success: false,
          message: 'userId and role are required',
          code: 'INVALID_INPUT',
        });
      }

      const user = await userModel.findOne({ id: userId });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
          code: 'USER_NOT_FOUND',
        });
      }

      const currentRoles = rbacService.normalizeRoles(user.roles || user.role);
      const check = rbacService.validateRoleAssignment(currentRoles, role);

      if (!check.valid) {
        return res.status(check.code === 'ROLE_NOT_FOUND' ? 404 : 409).json({
          success: false,
          message: check.reason,
          code: check.code,
        });
      }

      user.roles = Array.from(new Set([...currentRoles, role]));
      await user.save();

      res.status(200).json({
        success: true,
        message: 'Role assigned successfully',
        data: { id: user.id, roles: user.roles },
      });
    } catch (error) {
      console.error('Assign role error:', error);
      res.status(500).json({
        success: false,
        message: 'Role assignment failed',
        code: 'ROLE_ASSIGN_ERROR',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      });
    }
  }
}

module.exports = new RBACController();

/* USAGE:
const express = require('express');
const { authMiddleware } = require('../JWT-Authentication/Middleware');
const { requireRole, requirePermission } = require('./Middleware');
const rbacController = require('./Auth');

const app = express();
app.use(express.json());

app.get('/api/articles', authMiddleware, requirePermission('article:read'), (req, res) => {
  res.json({ message: 'Articles list' });
});

app.post('/api/reports', authMiddleware, requirePermission('report:create'), (req, res) => {
  res.json({ message: 'Report created' });
});

app.get('/api/roles', authMiddleware, requireRole('admin'), rbacController.listRoles);
app.get('/api/me/permissions', authMiddleware, rbacController.getMyPermissions);
app.post('/api/roles/assign', authMiddleware, requireRole('admin'), (req, res) =>
  rbacController.assignRole(req, res, userModel)
);
*/