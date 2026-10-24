// src/api/client.js
// Configured Axios instance with automatic JWT Authorization header injection.

import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

// Interceptor: inject Bearer token from localStorage
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('soc_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Interceptor: handle 401 Unauthorized globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // If we are not already on the login page, clear token
      if (window.location.pathname !== '/login') {
        localStorage.removeItem('soc_token');
        localStorage.removeItem('soc_user');
      }
    }
    return Promise.reject(error);
  }
);

export default api;
