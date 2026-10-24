// src/middleware/requestLogger.js
// Morgan HTTP request logger.
// In development we use the colourful "dev" format.
// In production we use "combined" (Apache-style, good for log aggregators).

import morgan from 'morgan';
import { config } from '../config/env.js';

const format = config.nodeEnv === 'production' ? 'combined' : 'dev';

export const requestLogger = morgan(format);
