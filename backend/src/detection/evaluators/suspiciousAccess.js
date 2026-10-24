// src/detection/evaluators/suspiciousAccess.js
// Pure evaluator: detects successful admin logins outside approved operating hours.
//
// Flags ssh_login_success events where the username matches a known admin user
// AND the timestamp (evaluated in UTC) falls outside allowed hours or on a weekend.
//
// Admin usernames are supplied via context — no database access or role fabrication.
//
// Inputs:
//   events  — Array of Event-like objects with { id, timestamp, eventType, username }
//   rule    — DetectionRule-like with config.{ allowedHoursStart, allowedHoursEnd, alertOnWeekend, targetRole }
//   context — { adminUsernames: Array<string> }
//             These are the OS/system usernames that correspond to admin accounts.
//             This mapping is the caller's responsibility — the evaluator does NOT infer
//             identity from generic usernames.
//
// Returns an array of match objects:
//   { dedupKey, triggeringEvents, metadata }

/**
 * @param {Array<object>} events  - Normalized event objects.
 * @param {object}        rule    - Detection rule with config.{ allowedHoursStart, allowedHoursEnd, alertOnWeekend }.
 * @param {object}        context - Must contain context.adminUsernames (array of strings).
 * @returns {Array<object>} Array of match descriptors; empty if no matches found.
 */
export function evaluate(events, rule, context) {
  const { allowedHoursStart, allowedHoursEnd, alertOnWeekend } = rule.config;
  const adminUsernames = (context && context.adminUsernames) || [];

  if (adminUsernames.length === 0) {
    return []; // No known admin usernames — cannot evaluate
  }

  // Build a case-insensitive lookup set for admin usernames
  const adminSet = new Set(adminUsernames.map((u) => u.toLowerCase()));

  // Filter to successful logins by admin usernames
  const relevant = events.filter(
    (e) =>
      e.eventType === 'ssh_login_success' &&
      e.username != null &&
      e.username !== '' &&
      adminSet.has(e.username.toLowerCase())
  );

  const matches = [];

  for (const evt of relevant) {
    const ts = new Date(evt.timestamp);
    const utcHour = ts.getUTCHours();
    const utcDay = ts.getUTCDay(); // 0 = Sunday, 6 = Saturday

    const isWeekend = utcDay === 0 || utcDay === 6;
    const isOutsideHours = utcHour < allowedHoursStart || utcHour >= allowedHoursEnd;

    const reasons = [];
    if (isOutsideHours) {
      reasons.push(`outside_hours (UTC ${utcHour}:00, allowed ${allowedHoursStart}:00–${allowedHoursEnd}:00)`);
    }
    if (alertOnWeekend && isWeekend) {
      reasons.push(`weekend_login (${['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][utcDay]})`);
    }

    if (reasons.length > 0) {
      matches.push({
        dedupKey: `suspicious_access::${evt.username}::${evt.id}`,
        triggeringEvents: [evt],
        metadata: {
          username: evt.username,
          utcHour,
          utcDay,
          isWeekend,
          isOutsideHours,
          reasons,
          timestamp: evt.timestamp,
        },
      });
    }
  }

  return matches;
}
