// src/detection/evaluators/portScan.js
// Pure evaluator: detects port-scanning activity.
//
// Groups connection_attempt events by srcIp and fires when the number
// of distinct destination ports within a sliding time window meets or
// exceeds the configured threshold.
//
// Inputs (all pure — no database access):
//   events  — Array of Event-like objects with { id, timestamp, eventType, srcIp, dstPort }
//   rule    — DetectionRule-like object with rule.config.{ portThreshold, windowSeconds, eventType }
//   context — (unused by this evaluator)
//
// Returns an array of match objects, each with:
//   { dedupKey, triggeringEvents, metadata }

/**
 * @param {Array<object>} events  - Normalized event objects.
 * @param {object}        rule    - Detection rule with config.{ portThreshold, windowSeconds, eventType }.
 * @returns {Array<object>} Array of match descriptors; empty if no matches found.
 */
export function evaluate(events, rule /*, context */) {
  const { portThreshold, windowSeconds, eventType } = rule.config;
  const windowMs = windowSeconds * 1000;

  const isMatchingEventType = (evtType) => {
    if (evtType === eventType) return true;
    // Allow connection_attempt and network_connection interchangeably to bridge parser and rule config
    if (
      (eventType === 'connection_attempt' && evtType === 'network_connection') ||
      (eventType === 'network_connection' && evtType === 'connection_attempt')
    ) {
      return true;
    }
    return false;
  };

  // 1. Filter to relevant events with valid srcIp and dstPort
  const relevant = events.filter(
    (e) =>
      isMatchingEventType(e.eventType) &&
      e.srcIp != null &&
      e.srcIp !== '' &&
      e.dstPort != null
  );

  // 2. Group by srcIp
  const groups = new Map();
  for (const evt of relevant) {
    if (!groups.has(evt.srcIp)) {
      groups.set(evt.srcIp, []);
    }
    groups.get(evt.srcIp).push(evt);
  }

  const matches = [];

  // 3. For each source IP, apply sliding window and count distinct dstPorts
  for (const [srcIp, groupEvents] of groups) {
    // Sort chronologically for deterministic evaluation
    groupEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    for (let i = 0; i < groupEvents.length; i++) {
      const windowStart = new Date(groupEvents[i].timestamp).getTime();
      const windowEnd = windowStart + windowMs;

      // Gather events in the window
      const windowEvents = [];
      const distinctPorts = new Set();

      for (let j = i; j < groupEvents.length; j++) {
        const ts = new Date(groupEvents[j].timestamp).getTime();
        if (ts <= windowEnd) {
          windowEvents.push(groupEvents[j]);
          distinctPorts.add(groupEvents[j].dstPort);
        } else {
          break;
        }
      }

      if (distinctPorts.size >= portThreshold) {
        matches.push({
          dedupKey: `port_scan::${srcIp}::${windowStart}`,
          triggeringEvents: windowEvents,
          metadata: {
            srcIp,
            distinctPortCount: distinctPorts.size,
            ports: [...distinctPorts].sort((a, b) => a - b),
            windowStartIso: new Date(windowStart).toISOString(),
            windowEndIso: new Date(windowEnd).toISOString(),
          },
        });
        // Skip past this burst to avoid overlapping duplicate matches
        break;
      }
    }
  }

  return matches;
}
