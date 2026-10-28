// src/middleware/errorHandler.js
// Global Express error handler.
// Any route/middleware that calls next(err) lands here.
// We log the error and return a consistent JSON response.

export function errorHandler(err, req, res, _next) {
  const status = err.status ?? err.statusCode ?? 500;
  const isDatabaseError = typeof err.code === 'string' && (err.code.startsWith('P') || err.code.startsWith('N/A'));
  const message = isDatabaseError && process.env.NODE_ENV === 'production'
    ? 'Internal database operation failed.'
    : (isDatabaseError ? 'Database operation failed.' : err.message ?? 'Internal Server Error');

  const body = {
    success: false,
    error: message,
  };

  console.error(`[ERROR] ${req.method} ${req.url} → ${status}: ${message}`);
  res.status(status).json(body);
}
