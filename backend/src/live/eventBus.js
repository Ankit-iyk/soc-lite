import { EventEmitter } from 'node:events';

const CHANNEL = 'soc-lite-live-update';
const emitter = new EventEmitter();
emitter.setMaxListeners(100);

export function publishLiveUpdate(type, payload = {}) {
  emitter.emit(CHANNEL, {
    type,
    payload,
    occurredAt: new Date().toISOString(),
  });
}

export function subscribeLiveUpdates(listener) {
  emitter.on(CHANNEL, listener);
  return () => emitter.off(CHANNEL, listener);
}
