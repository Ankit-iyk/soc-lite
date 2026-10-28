// src/modules/logs/logParser.js
// Deterministic log parsing and normalization engine for SOC Lite.
// Extracts structured fields without fabricating missing data.

import { isIP } from 'node:net';
import { Severity } from '@prisma/client';

// ── Validation Helpers ──────────────────────────────────────────────────────

/**
 * Validates whether a string is a valid IPv4 or IPv6 address.
 * Uses Node.js native RFC-compliant isIP parser.
 * @param {string} ip
 * @returns {boolean}
 */
export function isValidIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  return isIP(ip) !== 0;
}

/**
 * Validates whether a value is a valid TCP/UDP port (1 - 65535).
 * @param {number|string} port
 * @returns {number|null}
 */
export function validatePort(port) {
  if (port === null || port === undefined || port === '') return null;
  const num = parseInt(port, 10);
  if (!Number.isNaN(num) && num >= 1 && num <= 65535) {
    return num;
  }
  return null;
}

/**
 * Parses standard syslog timestamps (e.g. "Oct 24 10:15:32" or ISO format).
 * Syslog formats without a year assume the reference year. If the parsed date
 * is more than 1 day in the future (year-rollover edge case), it rolls back 1 year.
 * @param {string} dateStr
 * @param {Date} [referenceDate]
 * @returns {Date}
 */
export function parseLogTimestamp(dateStr, referenceDate = new Date()) {
  if (!dateStr || typeof dateStr !== 'string') return referenceDate;

  // 1. Try native ISO 8601 parsing first
  const isoParsed = new Date(dateStr);
  if (!Number.isNaN(isoParsed.getTime()) && (dateStr.includes('-') || dateStr.includes('T'))) {
    return isoParsed;
  }

  // 2. Parse traditional syslog header (e.g. "Oct 24 10:15:32")
  const syslogRegex = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/;
  const match = dateStr.trim().match(syslogRegex);
  if (match) {
    const months = {
      jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
      jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11
    };
    const month = months[match[1].toLowerCase()];
    if (month !== undefined) {
      const day = parseInt(match[2], 10);
      const hour = parseInt(match[3], 10);
      const min = parseInt(match[4], 10);
      const sec = parseInt(match[5], 10);

      const year = referenceDate.getFullYear();
      const parsed = new Date(year, month, day, hour, min, sec);

      // Check year rollover: if parsed date is > 1 day in future, use previous year
      const oneDayAhead = new Date(referenceDate.getTime() + 86400000);
      if (parsed > oneDayAhead) {
        parsed.setFullYear(year - 1);
      }
      return parsed;
    }
  }

  return referenceDate;
}

/**
 * Normalizes severity into a valid Prisma enum value.
 * @param {string} sev
 * @returns {Severity}
 */
export function normalizeSeverity(sev) {
  if (!sev || typeof sev !== 'string') return Severity.LOW;
  const upper = sev.trim().toUpperCase();
  if (upper in Severity) return Severity[upper];
  if (upper === 'WARN' || upper === 'WARNING') return Severity.MEDIUM;
  if (upper === 'ERR' || upper === 'ERROR') return Severity.HIGH;
  if (upper === 'FATAL') return Severity.CRITICAL;
  if (upper === 'DEBUG' || upper === 'INFO') return Severity.LOW;
  return Severity.LOW;
}

// ── Specific Format Parsers ─────────────────────────────────────────────────

/**
 * Format 1: Linux SSH / Syslog Auth Parser.
 * Handles failed passwords and accepted logins.
 * Note: Never fabricates dstPort — sets dstPort to null unless explicitly in log.
 */
export function parseSshAuthLog(line, receivedAt = new Date()) {
  const timestamp = parseLogTimestamp(line, receivedAt);

  // Extract hostname if present: e.g. "Oct 24 10:15:32 host-01 sshd[28412]: ..."
  const hostMatch = line.match(/^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+([^\s:]+)\s+sshd/);
  const hostname = hostMatch ? hostMatch[1] : null;

  // Case A: Failed login attempt
  // Example: Failed password for invalid user admin from 198.51.100.23 port 45231 ssh2
  // Example: Failed password for root from 198.51.100.23 port 54321 ssh2
  const failedMatch = line.match(/Failed password for (?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/i);
  if (failedMatch) {
    const rawIp = failedMatch[2];
    const srcIp = isValidIp(rawIp) ? rawIp : null;
    const srcPort = validatePort(failedMatch[3]);

    return {
      timestamp,
      eventType: 'ssh_login_failed',
      srcIp,
      dstIp: null, // Not present in syslog auth line
      srcPort,
      dstPort: null, // Never fabricate - null unless explicitly present
      username: failedMatch[1],
      hostname,
      message: 'Failed SSH password authentication',
      severity: Severity.HIGH,
      metadata: {
        rawSource: 'sshd',
        authMethod: 'password',
        isInvalidUser: line.includes('invalid user'),
      },
    };
  }

  // Case B: Accepted login
  // Example: Accepted publickey for analyst from 10.0.0.50 port 51234 ssh2
  // Example: Accepted password for admin from 10.0.0.50 port 51234 ssh2
  const acceptedMatch = line.match(/Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)/i);
  if (acceptedMatch) {
    const rawIp = acceptedMatch[3];
    const srcIp = isValidIp(rawIp) ? rawIp : null;
    const srcPort = validatePort(acceptedMatch[4]);

    return {
      timestamp,
      eventType: 'ssh_login_success',
      srcIp,
      dstIp: null,
      srcPort,
      dstPort: null,
      username: acceptedMatch[2],
      hostname,
      message: `Accepted SSH ${acceptedMatch[1]} authentication`,
      severity: Severity.LOW,
      metadata: {
        rawSource: 'sshd',
        authMethod: acceptedMatch[1].toLowerCase(),
      },
    };
  }

  return null;
}

/**
 * Format 2: Network Firewall Connection Parser.
 * Handles pfSense / iptables / filterlog connection logs.
 * Example: 2026-10-24T10:18:22Z FW-EDGE-01 filterlog: BLOCK,IN,4,TCP,203.0.113.88,10.0.0.1,58210,80
 */
export function parseFirewallLog(line, receivedAt = new Date()) {
  const fwRegex = /([^\s:]+)\s+filterlog:\s*([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),(\d+),(\d+)/i;
  const match = line.match(fwRegex);

  if (match) {
    const hostname = match[1];
    const action = match[2].toUpperCase(); // BLOCK or PASS
    const direction = match[3];
    const protocol = match[5].toUpperCase();
    const rawSrcIp = match[6];
    const rawDstIp = match[7];
    const srcPort = validatePort(match[8]);
    const dstPort = validatePort(match[9]);

    const srcIp = isValidIp(rawSrcIp) ? rawSrcIp : null;
    const dstIp = isValidIp(rawDstIp) ? rawDstIp : null;

    const timestamp = parseLogTimestamp(line, receivedAt);
    const severity = action === 'BLOCK' ? Severity.MEDIUM : Severity.LOW;

    return {
      timestamp,
      eventType: 'network_connection',
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      username: null, // Firewalls do not have OS usernames
      hostname,
      message: `Firewall ${action} on ${protocol} ${rawSrcIp}:${srcPort} -> ${rawDstIp}:${dstPort}`,
      severity,
      metadata: {
        action,
        direction,
        protocol,
      },
    };
  }

  return null;
}

/**
 * Format 3: Structured JSON Log Parser.
 * Parses JSON strings and safely validates types. Extra properties are saved in metadata.
 */
export function parseJsonLog(rawContent, receivedAt = new Date()) {
  let parsed;
  try {
    parsed = JSON.parse(rawContent);
  } catch {
    return null; // Not valid JSON
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }

  const timestamp = parsed.timestamp ? parseLogTimestamp(parsed.timestamp, receivedAt) : receivedAt;
  const eventType = typeof parsed.eventType === 'string' && parsed.eventType.trim()
    ? parsed.eventType.trim()
    : 'json_event';

  const srcIp = isValidIp(parsed.srcIp) ? parsed.srcIp : null;
  const dstIp = isValidIp(parsed.dstIp) ? parsed.dstIp : null;
  const srcPort = validatePort(parsed.srcPort);
  const dstPort = validatePort(parsed.dstPort);
  const username = typeof parsed.username === 'string' ? parsed.username.trim() : null;
  const hostname = typeof parsed.hostname === 'string' ? parsed.hostname.trim() : null;
  const message = typeof parsed.message === 'string' ? parsed.message.trim() : null;
  const severity = normalizeSeverity(parsed.severity);

  // Preserve any remaining fields in metadata
  const knownKeys = ['timestamp', 'eventType', 'srcIp', 'dstIp', 'srcPort', 'dstPort', 'username', 'hostname', 'message', 'severity', 'metadata'];
  const extraMetadata = {};
  for (const [key, val] of Object.entries(parsed)) {
    if (!knownKeys.includes(key)) {
      extraMetadata[key] = val;
    }
  }

  const combinedMetadata = {
    ...extraMetadata,
    ...(parsed.metadata && typeof parsed.metadata === 'object' ? parsed.metadata : {}),
  };

  return {
    timestamp,
    eventType,
    srcIp,
    dstIp,
    srcPort,
    dstPort,
    username,
    hostname,
    message,
    severity,
    metadata: Object.keys(combinedMetadata).length > 0 ? combinedMetadata : null,
  };
}

/**
 * Normalizes fields extracted from a Windows Event XML record by the collector.
 * The original XML remains stored separately as the RawLog content.
 */
export function parseWindowsEventRecord(record, receivedAt = new Date()) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;

  const eventId = Number(record.eventId);
  if (!Number.isInteger(eventId) || eventId < 0) return null;

  const details = record.details && typeof record.details === 'object' && !Array.isArray(record.details)
    ? record.details
    : {};
  const field = (...names) => {
    for (const name of names) {
      const value = details[name];
      if (typeof value === 'string' && value.trim()) return value.trim();
    }
    return null;
  };

  const timestamp = typeof record.timeCreated === 'string'
    ? parseLogTimestamp(record.timeCreated, receivedAt)
    : receivedAt;
  const eventType = eventId === 4625
    ? 'windows_failed_logon'
    : eventId === 4624
      ? 'windows_successful_logon'
      : 'windows_event';
  const rawIp = field('IpAddress', 'SourceIp', 'SourceAddress');
  const rawUsername = field('TargetUserName', 'AccountName', 'UserName');

  return {
    timestamp,
    eventType,
    srcIp: isValidIp(rawIp) ? rawIp : null,
    dstIp: null,
    srcPort: validatePort(field('IpPort', 'SourcePort')),
    dstPort: null,
    username: rawUsername === '-' ? null : rawUsername,
    hostname: typeof record.hostname === 'string' ? record.hostname.trim() || null : null,
    message: typeof record.message === 'string' && record.message.trim()
      ? record.message.trim()
      : `Windows Event ID ${eventId}`,
    severity: eventId === 4625 ? Severity.HIGH : Severity.LOW,
    metadata: {
      eventId,
      eventRecordId: record.eventRecordId == null ? null : String(record.eventRecordId),
      channel: typeof record.channel === 'string' ? record.channel : null,
      provider: typeof record.provider === 'string' ? record.provider : null,
      userSid: typeof record.userSid === 'string' ? record.userSid : null,
      details,
    },
  };
}

/**
 * Format 4: Generic Fallback Parser.
 * Used when no specific parser matches or for malformed lines.
 * Guarantees zero data loss without inventing fields.
 */
export function parseGenericFallback(rawContent, receivedAt = new Date()) {
  const preview = rawContent.length > 250 ? `${rawContent.substring(0, 247)}…` : rawContent;

  return {
    timestamp: receivedAt,
    eventType: 'unknown',
    srcIp: null,
    dstIp: null,
    srcPort: null,
    dstPort: null,
    username: null,
    hostname: null,
    message: preview,
    severity: Severity.LOW,
    metadata: {
      unparsed: true,
      originalLength: rawContent.length,
    },
  };
}

// ── Orchestrator ────────────────────────────────────────────────────────────

/**
 * Orchestrator: Dispatches to the appropriate parser based on source hint or content.
 * @param {string} source - e.g. "auth.log", "firewall", "json", "syslog"
 * @param {string} rawContent - The unparsed log line
 * @param {Date} [receivedAt]
 * @returns {object} Normalized event attributes
 */
export function normalizeLog(source, rawContent, receivedAt = new Date()) {
  const trimmed = (rawContent || '').trim();
  const lowerSource = (source || '').toLowerCase();

  // 1. JSON log source or JSON content
  if (lowerSource === 'json' || trimmed.startsWith('{')) {
    const jsonResult = parseJsonLog(trimmed, receivedAt);
    if (jsonResult) return jsonResult;
  }

  // 2. SSH / Syslog Auth
  if (lowerSource.includes('auth') || lowerSource.includes('ssh') || trimmed.includes('sshd[')) {
    const sshResult = parseSshAuthLog(trimmed, receivedAt);
    if (sshResult) return sshResult;
  }

  // 3. Firewall / Filterlog
  if (lowerSource.includes('firewall') || lowerSource.includes('filterlog') || trimmed.includes('filterlog:')) {
    const fwResult = parseFirewallLog(trimmed, receivedAt);
    if (fwResult) return fwResult;
  }

  // 4. Try SSH / Firewall even without explicit source hint
  const sshFallback = parseSshAuthLog(trimmed, receivedAt);
  if (sshFallback) return sshFallback;

  const fwFallback = parseFirewallLog(trimmed, receivedAt);
  if (fwFallback) return fwFallback;

  // 5. Generic fallback (safe, zero data loss, no invented fields)
  return parseGenericFallback(trimmed, receivedAt);
}
