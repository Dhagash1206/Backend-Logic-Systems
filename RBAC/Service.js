// RBAC Service - Role definitions, hierarchy resolution, permission checks and separation of duties
// Permission format: "resource:action" (wildcards allowed, e.g. "report:*", "*:read", "*:*")

class RBACService {
    constructor(config = {}) {
        this.defaultRole = config.defaultRole || 'guest';
        this.separationOfDuties = config.separationOfDuties || [
            ['approver', 'requester'], // a user cannot hold both roles
        ];

        this.roles = new Map();
        this.resolvedCache = new Map();

        const initialRoles = config.roles || RBACService.defaultRoles();
        for (const [name, definition] of Object.entries(initialRoles)) {
            this.roles.set(name, {
                inherits: definition.inherits || [],
                permissions: definition.permissions || [],
            });
        }

        this.validateHierarchy();
    }

    static defaultRoles() {
        return {
            guest: { permissions: ['article:read'] },
            user: { inherits: ['guest'], permissions: ['profile:read', 'profile:update'] },
            manager: { inherits: ['user'], permissions: ['report:read', 'report:create', 'user:read'] },
            admin: { inherits: ['manager'], permissions: ['*:*'] },
        };
    }

    // Role management
    defineRole(name, { inherits = [], permissions = [] } = {}) {
        if (!name || typeof name !== 'string') {
            throw new Error('Role name must be a non-empty string');
        }

        permissions.forEach((p) => this.assertPermissionFormat(p));

        const previous = this.roles.get(name);
        this.roles.set(name, { inherits, permissions });

        try {
            this.validateHierarchy();
        } catch (error) {
            // Roll back so a bad definition never leaves the system in an invalid state
            if (previous) this.roles.set(name, previous);
            else this.roles.delete(name);
            throw error;
        }

        this.resolvedCache.clear();
    }

    removeRole(name) {
        for (const [roleName, role] of this.roles.entries()) {
            if (role.inherits.includes(name)) {
                throw new Error(`Cannot remove role "${name}": inherited by "${roleName}"`);
            }
        }

        this.roles.delete(name);
        this.resolvedCache.clear();
    }

    roleExists(name) {
        return this.roles.has(name);
    }

    listRoles() {
        return Array.from(this.roles.entries()).map(([name, role]) => ({
            name,
            inherits: role.inherits,
            permissions: this.getRolePermissions(name),
        }));
    }

    // Hierarchy and permission resolution
    getRolePermissions(roleName) {
        if (this.resolvedCache.has(roleName)) {
            return this.resolvedCache.get(roleName);
        }

        const role = this.roles.get(roleName);
        if (!role) return [];

        const resolved = new Set(role.permissions);
        for (const parent of role.inherits) {
            this.getRolePermissions(parent).forEach((p) => resolved.add(p));
        }

        const result = Array.from(resolved);
        this.resolvedCache.set(roleName, result);
        return result;
    }

    getUserPermissions(roles) {
        const merged = new Set();
        this.normalizeRoles(roles).forEach((role) => {
            this.getRolePermissions(role).forEach((p) => merged.add(p));
        });
        return Array.from(merged);
    }

    // Permission checks (deny by default - least privilege)
    hasPermission(roles, permission) {
        this.assertPermissionFormat(permission);
        return this.getUserPermissions(roles).some((granted) => this.matches(granted, permission));
    }

    hasAnyPermission(roles, permissions = []) {
        return permissions.some((p) => this.hasPermission(roles, p));
    }

    hasAllPermissions(roles, permissions = []) {
        return permissions.every((p) => this.hasPermission(roles, p));
    }

    hasRole(roles, requiredRole) {
        return this.normalizeRoles(roles).includes(requiredRole);
    }

    // True if the user holds the required role or any role that inherits from it
    hasRoleOrHigher(roles, requiredRole) {
        return this.normalizeRoles(roles).some(
            (role) => role === requiredRole || this.inheritsFrom(role, requiredRole)
        );
    }

    inheritsFrom(roleName, ancestor, visited = new Set()) {
        if (visited.has(roleName)) return false;
        visited.add(roleName);

        const role = this.roles.get(roleName);
        if (!role) return false;

        return role.inherits.some(
            (parent) => parent === ancestor || this.inheritsFrom(parent, ancestor, visited)
        );
    }

    // Separation of duties
    validateRoleAssignment(currentRoles, newRole) {
        if (!this.roleExists(newRole)) {
            return { valid: false, code: 'ROLE_NOT_FOUND', reason: `Role "${newRole}" does not exist` };
        }

        const combined = new Set([...this.normalizeRoles(currentRoles), newRole]);

        for (const conflictSet of this.separationOfDuties) {
            const held = conflictSet.filter((role) => combined.has(role));
            if (held.length > 1) {
                return {
                    valid: false,
                    code: 'SOD_VIOLATION',
                    reason: `Roles [${held.join(', ')}] cannot be held by the same user`,
                };
            }
        }

        return { valid: true, code: null, reason: null };
    }

    // Helpers
    normalizeRoles(roles) {
        if (!roles) return [this.defaultRole];
        return Array.isArray(roles) ? roles : [roles];
    }

    matches(granted, requested) {
        const [grantedResource, grantedAction] = granted.split(':');
        const [requestedResource, requestedAction] = requested.split(':');

        const resourceOk = grantedResource === '*' || grantedResource === requestedResource;
        const actionOk = grantedAction === '*' || grantedAction === requestedAction;

        return resourceOk && actionOk;
    }

    assertPermissionFormat(permission) {
        if (typeof permission !== 'string' || !/^[\w*-]+:[\w*-]+$/.test(permission)) {
            throw new Error(`Invalid permission format "${permission}". Expected "resource:action"`);
        }
    }

    validateHierarchy() {
        const visiting = new Set();
        const visited = new Set();

        const visit = (name) => {
            if (visited.has(name)) return;
            if (visiting.has(name)) {
                throw new Error(`Circular role inheritance detected at "${name}"`);
            }

            visiting.add(name);
            const role = this.roles.get(name);

            for (const parent of role.inherits) {
                if (!this.roles.has(parent)) {
                    throw new Error(`Role "${name}" inherits from unknown role "${parent}"`);
                }
                visit(parent);
            }

            visiting.delete(name);
            visited.add(name);
        };

        for (const name of this.roles.keys()) visit(name);
    }
}

module.exports = new RBACService();
module.exports.RBACService = RBACService;