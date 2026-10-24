// src/detection/evaluators/sshBruteForce.js
// Pure evaluator: detects SSH brute-force login attempts.
//
// Groups ssh_login_failed events by (srcIp, username) and fires when
// the count within a sliding time window meets or exceeds the threshold.
//
// Inputs (all pure — no database access):
//   events  — Array of Event-like objects with { id, timestamp, eventType, srcIp, username }
//   rule    — DetectionRule-like object with rule.config.{ threshold, windowSeconds, eventType }
//   context — (unused by this evaluator)
//
// Returns an array of match objects, each with:
//   { dedupKey, triggeringEvents, metadata }

/**
 * @param {Array<object>} events  - Normalized event objects (must include timestamp, eventType, srcIp, username).
 * @param {object}        rule    - Detection rule with config.{ threshold, windowSeconds, eventType }.
 * @returns {Array<object>} Array of match descriptors; empty if no matches found.
 */
export function evaluate(events, rule /*, context */) {
  const { threshold, windowSeconds, eventType } = rule.config;
  const windowMs = windowSeconds * 1000;

  // 1. Filter to only the relevant event type with valid grouping fields
  const relevant = events.filter(
    (e) =>
      e.eventType === eventType &&
      e.srcIp != null &&
      e.srcIp !== '' &&
      e.username != null &&
      e.username !== ''
  );

  // 2. Group by composite key: srcIp + username
  const groups = new Map();
  for (const evt of relevant) {
    const key = `${evt.srcIp}||${evt.username}`;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(evt);
  }

  const matches = [];

  // 3. For each group, apply a sliding window to detect bursts
  for (const [key, groupEvents] of groups) {
    // Sort chronologically (ascending) for deterministic window evaluation
    groupEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    // Sliding window: for each event as window start, count how many fall
    // within [start, start + windowMs] (inclusive on both boundaries).
    for (let i = 0; i <= groupEvents.length - threshold; i++) {
      const windowStart = new Date(groupEvents[i].timestamp).getTime();
      const windowEnd = windowStart + windowMs;

      // Collect events that fall within the window
      const windowEvents = [];
      for (let j = i; j < groupEvents.length; j++) {
        const ts = new Date(groupEvents[j].timestamp).getTime();
        if (ts <= windowEnd) {
          windowEvents.push(groupEvents[j]);
        } else {
          break; // sorted, no further events can be in window
        }
      }

      if (windowEvents.length >= threshold) {
        const [srcIp, username] = key.split('||');
        matches.push({
          dedupKey: `ssh_brute_force::${srcIp}::${username}::${windowStart}`,
          triggeringEvents: windowEvents,
          metadata: {
            srcIp,
            username,
            count: windowEvents.length,
            windowStartIso: new Date(windowStart).toISOString(),
            windowEndIso: new Date(windowEnd).toISOString(),
          },
        });
        // Skip ahead past this window to avoid duplicate matches for
        // overlapping windows within the same burst.
        break;
      }
    }
  }

  return matches;
}
