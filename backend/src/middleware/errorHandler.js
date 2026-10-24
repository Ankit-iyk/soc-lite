// src/middleware/errorHandler.js
// Global Express error handler.
// Any route/middleware that calls next(err) lands here.
// We log the error and return a consistent JSON response.

export function errorHandler(err, req, res, _next) {
  const status = err.status ?? err.statusCode ?? 500;
  const message = err.message ?? 'Internal Server Error';

  // Don't leak stack traces to the client in production
  const body = {
    success: false,
    error: message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  };

  console.error(`[ERROR] ${req.method} ${req.url} → ${status}: ${message}`);
  res.status(status).json(body);
}
