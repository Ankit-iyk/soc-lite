// src/modules/auth/auth.controller.js
// Authentication controllers: login, logout, and current user profile.

import bcrypt from 'bcryptjs';
import prisma from '../../config/prisma.js';
import { signToken } from '../../utils/jwt.js';

export async function login(req, res, next) {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required.',
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

    // Query user by email
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user) {
      // Audit failed login attempt (do not disclose if user exists)
      await prisma.auditLog.create({
        data: {
          action: 'LOGIN_FAILURE',
          targetType: 'User',
          ipAddress: clientIp,
          details: { email: normalizedEmail, reason: 'User not found' },
        },
      }).catch(err => console.error('AuditLog error:', err.message));

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password.',
      });
    }

    // Verify password hash
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      // Audit failed password attempt
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'LOGIN_FAILURE',
          targetType: 'User',
          targetId: user.id,
          ipAddress: clientIp,
          details: { email: normalizedEmail, reason: 'Incorrect password' },
        },
      }).catch(err => console.error('AuditLog error:', err.message));

      return res.status(401).json({
        success: false,
        error: 'Invalid email or password.',
      });
    }

    // Generate JWT token
    const token = signToken({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    // Audit successful login
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        targetType: 'User',
        targetId: user.id,
        ipAddress: clientIp,
        details: { email: user.email, role: user.role },
      },
    }).catch(err => console.error('AuditLog error:', err.message));

    return res.json({
      success: true,
      message: 'Login successful.',
      data: {
        token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
      },
    });
  } catch (err) {
    next(err);
  }
}

export async function logout(req, res, next) {
  try {
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';

    if (req.user) {
      await prisma.auditLog.create({
        data: {
          userId: req.user.id,
          action: 'LOGOUT',
          targetType: 'User',
          targetId: req.user.id,
          ipAddress: clientIp,
          details: { email: req.user.email },
        },
      }).catch(err => console.error('AuditLog error:', err.message));
    }

    return res.json({
      success: true,
      message: 'Logout successful.',
    });
  } catch (err) {
    next(err);
  }
}

export async function getMe(req, res) {
  return res.json({
    success: true,
    data: {
      user: req.user,
    },
  });
}
