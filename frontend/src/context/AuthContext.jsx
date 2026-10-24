// src/context/AuthContext.jsx
// Manages authentication state, user session, and token persistence.

import { useState, useEffect, useCallback } from 'react';
import { AuthContext } from './auth-context';
import { loginApi, logoutApi, getMeApi } from '../api/auth.api';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('soc_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState(() => localStorage.getItem('soc_token') || null);
  const [isLoading, setIsLoading] = useState(true);

  // Validate existing token on mount
  useEffect(() => {
    let mounted = true;

    async function verifyAuth() {
      const storedToken = localStorage.getItem('soc_token');
      if (!storedToken) {
        if (mounted) setIsLoading(false);
        return;
      }

      try {
        const res = await getMeApi();
        if (mounted && res?.success && res.data?.user) {
          setUser(res.data.user);
          localStorage.setItem('soc_user', JSON.stringify(res.data.user));
        }
      } catch {
        if (mounted) {
          setUser(null);
          setToken(null);
          localStorage.removeItem('soc_token');
          localStorage.removeItem('soc_user');
        }
      } finally {
        if (mounted) setIsLoading(false);
      }
    }

    verifyAuth();
    return () => { mounted = false; };
  }, []);

  const login = useCallback(async (email, password) => {
    const res = await loginApi({ email, password });
    if (res?.success && res.data?.token) {
      setToken(res.data.token);
      setUser(res.data.user);
      localStorage.setItem('soc_token', res.data.token);
      localStorage.setItem('soc_user', JSON.stringify(res.data.user));
      return res.data.user;
    }
    throw new Error(res?.error || 'Login failed');
  }, []);

  const logout = useCallback(async () => {
    try {
      if (token) {
        await logoutApi();
      }
    } catch {
      // Ignore API logout error during cleanup
    } finally {
      setUser(null);
      setToken(null);
      localStorage.removeItem('soc_token');
      localStorage.removeItem('soc_user');
    }
  }, [token]);

  const value = {
    user,
    token,
    isAuthenticated: Boolean(user && token),
    isLoading,
    login,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
