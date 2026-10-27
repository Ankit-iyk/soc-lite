// src/middleware/agentAuth.js
// Middleware: Authenticates requests from Windows Event Log collector agents.
//
// Agents authenticate via a scoped "Agent Token" API key — never a user JWT.
// The raw token is sent in the "X-Agent-Token" header.
// The server bcrypt-compares it against the stored hash (constant-time comparison).
//
// Security properties:
//   • Raw token is never stored on the server — only its bcrypt hash.
//   • Tokens can be individually revoked by setting enabled=false.
//   • lastUsedAt is updated on every successful authentication.
//   • Attaches req.agentToken = { id, name, collectorStatus } for downstream use.

import bcrypt from 'bcryptjs';
import prisma from '../config/prisma.js';

const HEADER = 'x-agent-token';

/**
 * Middleware: Validate an agent API token from the X-Agent-Token header.
 * Attaches req.agentToken on success.
 */
export async function requireAgentAuth(req, res, next) {
  try {
    const rawToken = req.headers[HEADER];

    if (!rawToken || typeof rawToken !== 'string' || !rawToken.trim()) {
      return res.status(401).json({
        success: false,
        error: 'Agent authentication required. Missing X-Agent-Token header.',
      });
    }

    // Fetch all enabled tokens — we cannot look up by raw value since we only
    // store bcrypt hashes. We limit this to enabled tokens to reduce the set.
    // bcrypt.compare is constant-time, so this is safe.
    //
    // Performance note: the expected number of enrolled agents is small (< 100).
    // For large deployments, a prefix scheme or separate indexed lookup field
    // would be needed. For SOC Lite's threat-lab scale this is appropriate.
    const enabledTokens = await prisma.agentToken.findMany({
      where: { enabled: true, revokedAt: null },
      include: { collectorStatus: true },
    });

    let matchedToken = null;
    for (const token of enabledTokens) {
      const isMatch = await bcrypt.compare(rawToken.trim(), token.tokenHash);
      if (isMatch) {
        matchedToken = token;
        break;
      }
    }

    if (!matchedToken) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or revoked agent token.',
      });
    }

    // Update lastUsedAt asynchronously — don't block the request
    prisma.agentToken
      .update({
        where: { id: matchedToken.id },
        data: { lastUsedAt: new Date() },
      })
      .catch((err) => console.error('[AgentAuth] lastUsedAt update failed:', err.message));

    req.agentToken = matchedToken;
    next();
  } catch (err) {
    next(err);
  }
}
