// Pure evaluator: detects repeated Windows failed logons (Event ID 4625).

export function evaluate(events, rule) {
  const { threshold, windowSeconds } = rule.config;
  const windowMs = windowSeconds * 1000;
  const groups = new Map();

  for (const event of events) {
    if (event.eventType !== 'windows_failed_logon' || !event.hostname || !event.username) continue;

    const key = JSON.stringify([event.hostname, event.srcIp || 'unknown', event.username]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }

  const matches = [];
  for (const [key, group] of groups) {
    group.sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));

    for (let start = 0; start <= group.length - threshold; start++) {
      const windowStart = new Date(group[start].timestamp).getTime();
      const triggeringEvents = [];
      for (let index = start; index < group.length; index++) {
        if (new Date(group[index].timestamp).getTime() > windowStart + windowMs) break;
        triggeringEvents.push(group[index]);
      }

      if (triggeringEvents.length < threshold) continue;

      const [hostname, srcIp, username] = JSON.parse(key);
      matches.push({
        dedupKey: `windows_failed_logon::${hostname}::${srcIp}::${username}::${windowStart}`,
        triggeringEvents,
        metadata: {
          hostname,
          srcIp: srcIp === 'unknown' ? null : srcIp,
          username,
          count: triggeringEvents.length,
          windowStartIso: new Date(windowStart).toISOString(),
          windowEndIso: new Date(windowStart + windowMs).toISOString(),
        },
      });
      break;
    }
  }

  return matches;
}