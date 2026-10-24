// src/detection/evaluators/suspiciousIp.js
// Pure evaluator: flags events where srcIp or dstIp matches a known threat indicator.
//
// Indicators are passed in via context — no database access is performed.
//
// Inputs:
//   events  — Array of Event-like objects with { id, timestamp, srcIp, dstIp, eventType }
//   rule    — DetectionRule-like object with rule.config.{ matchSource, matchDestination }
//   context — { indicators: Array<{ value: string, type: string, confidence: number, source: string }> }
//             Only indicators with type 'IP' are relevant.
//
// Returns an array of match objects, one per matching event:
//   { dedupKey, triggeringEvents, metadata }

/**
 * @param {Array<object>} events  - Normalized event objects.
 * @param {object}        rule    - Detection rule with config.{ matchSource, matchDestination }.
 * @param {object}        context - Must contain context.indicators (array of IOCs).
 * @returns {Array<object>} Array of match descriptors; empty if no matches found.
 */
export function evaluate(events, rule, context) {
  const { matchSource, matchDestination } = rule.config;
  const indicators = (context && context.indicators) || [];

  // Build a lookup Set of known-bad IPs for O(1) matching
  const badIpSet = new Set();
  const indicatorMap = new Map(); // value → full indicator details
  for (const ioc of indicators) {
    if (ioc.type === 'IP') {
      badIpSet.add(ioc.value);
      indicatorMap.set(ioc.value, ioc);
    }
  }

  if (badIpSet.size === 0) {
    return []; // No IP indicators — nothing to match
  }

  const matches = [];

  for (const evt of events) {
    const matchedIndicators = [];

    if (matchSource && evt.srcIp && badIpSet.has(evt.srcIp)) {
      matchedIndicators.push({
        field: 'srcIp',
        ip: evt.srcIp,
        indicator: indicatorMap.get(evt.srcIp),
      });
    }

    if (matchDestination && evt.dstIp && badIpSet.has(evt.dstIp)) {
      matchedIndicators.push({
        field: 'dstIp',
        ip: evt.dstIp,
        indicator: indicatorMap.get(evt.dstIp),
      });
    }

    if (matchedIndicators.length > 0) {
      // Build a dedupKey per event+matched-IPs to ensure unique alerts
      const matchedIps = matchedIndicators.map((m) => `${m.field}:${m.ip}`).join('|');
      matches.push({
        dedupKey: `suspicious_ip::${evt.id}::${matchedIps}`,
        triggeringEvents: [evt],
        metadata: {
          matchedIndicators,
          eventType: evt.eventType,
          timestamp: evt.timestamp,
        },
      });
    }
  }

  return matches;
}
