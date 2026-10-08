// RBAC Middleware - Route-level authorization || handle forbidden access
// Must run AFTER the JWT authMiddleware so that req.user is populated

const rbacService = require('./Service');

const denyUnauthenticated = (res) =>
    res.status(401).json({
        success: false,
        message: 'User not authenticated',
        code: 'AUTH_REQUIRED',
    });

const denyForbidden = (res, message = 'Insufficient permissions') =>
    res.status(403).json({
        success: false,
        message,
        code: 'AUTH_FORBIDDEN',
    });

const getRoles = (req) => req.user.roles || req.user.role;


// Requires at least one of the listed roles (hierarchy aware)
const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) return denyUnauthenticated(res);

        const allowed = allowedRoles.some((role) => rbacService.hasRoleOrHigher(getRoles(req), role));
        if (!allowed) return denyForbidden(res);

        next();
    };
};


// Requires ALL listed permissions
const requirePermission = (...permissions) => {
    return (req, res, next) => {
        try {
            if (!req.user) return denyUnauthenticated(res);

            if (!rbacService.hasAllPermissions(getRoles(req), permissions)) {
                return denyForbidden(res);
            }

            next();
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: 'Permission check failed',
                code: 'RBAC_ERROR',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined,
            });
        }
    };
};


// Requires AT LEAST ONE of the listed permissions
const requireAnyPermission = (...permissions) => {
    return (req, res, next) => {
        try {
            if (!req.user) return denyUnauthenticated(res);

            if (!rbacService.hasAnyPermission(getRoles(req), permissions)) {
                return denyForbidden(res);
            }

            next();
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: 'Permission check failed',
                code: 'RBAC_ERROR',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined,
            });
        }
    };
};


// Resource owner OR holder of an override permission (e.g. "order:manage")
const requireOwnerOrPermission = (getOwnerId, overridePermission) => {
    return async (req, res, next) => {
        try {
            if (!req.user) return denyUnauthenticated(res);

            if (rbacService.hasPermission(getRoles(req), overridePermission)) return next();

            const ownerId = await getOwnerId(req);
            if (ownerId && String(ownerId) === String(req.user.id)) return next();

            return denyForbidden(res);
        } catch (error) {
            return res.status(500).json({
                success: false,
                message: 'Ownership check failed',
                code: 'RBAC_ERROR',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined,
            });
        }
    };
};

module.exports = {
    requireRole,
    requirePermission,
    requireAnyPermission,
    requireOwnerOrPermission,
};