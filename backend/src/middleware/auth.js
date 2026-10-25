// src/middleware/auth.js
// Authentication & Role-Based Access Control (RBAC) middleware.

import { verifyToken } from '../utils/jwt.js';
import prisma from '../config/prisma.js';

/**
 * Middleware: Requires a valid Bearer JWT token in Authorization header.
 * Attaches the authenticated user (without password hash) to req.user.
 */
export async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required. Missing or malformed Bearer token.',
      });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = verifyToken(token);
    } catch (err) {
      const isExpired = err.name === 'TokenExpiredError';
      return res.status(401).json({
        success: false,
        error: isExpired ? 'Token expired. Please log in again.' : 'Invalid authentication token.',
      });
    }

    if (!decoded.userId) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token payload.',
      });
    }

    // Verify user still exists in database
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User associated with this token no longer exists.',
      });
    }

    req.user = user;
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Middleware factory: Enforces specific Role-Based Access Control (RBAC).
 * Must be placed after requireAuth in route chains.
 * @param {...string} allowedRoles - e.g. 'ADMIN', 'ANALYST'
 */
export function requireRole(...allowedRoles) {
  const roles = allowedRoles.flat();
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required before checking permissions.',
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Requires one of: [${roles.join(', ')}]. Current role: ${req.user.role}`,
      });
    }

    next();
  };
}
