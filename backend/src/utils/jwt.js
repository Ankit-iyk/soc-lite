// src/utils/jwt.js
// JWT token generation and verification utility.

import jwt from 'jsonwebtoken';
import { config } from '../config/env.js';

/**
 * Sign a payload into a signed JWT token.
 * @param {object} payload - Claims to embed in token (userId, role, etc.)
 * @param {object} [options] - Additional jsonwebtoken sign options
 * @returns {string} Signed JWT token string
 */
export function signToken(payload, options = {}) {
  if (!config.jwtSecret) {
    throw new Error('JWT_SECRET is not configured in backend/.env');
  }

  return jwt.sign(payload, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn || '8h',
    ...options,
  });
}

/**
 * Verify and decode a JWT token.
 * @param {string} token - Raw JWT token
 * @returns {object} Decoded token payload
 * @throws {Error} If token is invalid or expired
 */
export function verifyToken(token) {
  if (!config.jwtSecret) {
    throw new Error('JWT_SECRET is not configured in backend/.env');
  }

  return jwt.verify(token, config.jwtSecret);
}
