import { subscribeLiveUpdates } from '../../live/eventBus.js';

export function streamDashboardUpdates(req, res) {
  res.status(200);
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();

  const send = (update) => {
    res.write(`event: ${update.type}\n`);
    res.write(`data: ${JSON.stringify(update)}\n\n`);
  };

  send({
    type: 'connected',
    payload: { role: req.user.role },
    occurredAt: new Date().toISOString(),
  });

  const unsubscribe = subscribeLiveUpdates(send);
  const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 15_000);

  req.on('close', () => {
    clearInterval(heartbeat);
    unsubscribe();
  });
}
