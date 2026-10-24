// src/api/auth.api.js
// Authentication API endpoints.

import api from './client';

export async function loginApi({ email, password }) {
  const response = await api.post('/auth/login', { email, password });
  return response.data;
}

export async function logoutApi() {
  const response = await api.post('/auth/logout');
  return response.data;
}

export async function getMeApi() {
  const response = await api.get('/auth/me');
  return response.data;
}
