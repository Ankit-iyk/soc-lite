// src/pages/Login.jsx
// Cyber-themed login portal with JWT authentication and demo credential presets.

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, Eye, EyeOff, AlertCircle, ArrowRight, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

const DEMO_PRESETS = [
  { role: 'ADMIN', label: 'Admin', email: 'admin@soclite.local', pass: 'Admin@SOC2026!' },
  { role: 'ANALYST', label: 'Analyst', email: 'analyst@soclite.local', pass: 'Analyst@SOC2026!' },
  { role: 'VIEWER', label: 'Viewer', email: 'viewer@soclite.local', pass: 'Viewer@SOC2026!' },
];

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();

  const [email, setEmail] = useState('analyst@soclite.local');
  const [password, setPassword] = useState('Analyst@SOC2026!');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      await login(email, password);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSubmitting(false);
    }
  }

  function applyPreset(preset) {
    setEmail(preset.email);
    setPassword(preset.pass);
    setError('');
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'var(--color-bg-base)',
      backgroundImage: 'radial-gradient(ellipse at 50% 20%, rgba(0, 212, 170, 0.08) 0%, transparent 70%)',
      padding: '1.5rem',
      fontFamily: 'var(--font-sans)',
      color: 'var(--color-text-primary)',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '440px',
        backgroundColor: 'var(--color-bg-card)',
        border: '1px solid var(--color-border)',
        borderRadius: 'var(--radius-card)',
        padding: '2.5rem 2rem',
        boxShadow: 'var(--shadow-card)',
        position: 'relative',
        overflow: 'hidden',
      }}>
        {/* Cyber glow bar on top */}
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '3px',
          background: 'linear-gradient(90deg, transparent, var(--color-accent), transparent)',
        }} />

        {/* Brand header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div style={{
            width: '52px',
            height: '52px',
            margin: '0 auto 1rem',
            borderRadius: '12px',
            backgroundColor: 'rgba(0, 212, 170, 0.12)',
            border: '1px solid rgba(0, 212, 170, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: 'var(--shadow-glow)',
          }}>
            <Shield size={28} color="var(--color-accent)" />
          </div>
          <h1 style={{
            fontSize: '1.4rem',
            fontWeight: 700,
            letterSpacing: '0.04em',
            margin: '0 0 0.3rem',
            color: 'var(--color-text-primary)',
          }}>
            SOC <span style={{ color: 'var(--color-accent)' }}>Lite</span>
          </h1>
          <p style={{
            fontSize: '0.82rem',
            color: 'var(--color-text-secondary)',
            margin: 0,
            letterSpacing: '0.02em',
          }}>
            Security Operations & Threat Defense
          </p>
        </div>

        {/* Error banner */}
        {error && (
          <div style={{
            backgroundColor: 'rgba(255, 59, 59, 0.1)',
            border: '1px solid rgba(255, 59, 59, 0.3)',
            borderRadius: '6px',
            padding: '0.75rem 1rem',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
            fontSize: '0.82rem',
            color: 'var(--color-critical)',
          }}>
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit}>
          {/* Email field */}
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{
              display: 'block',
              fontSize: '0.78rem',
              fontWeight: 500,
              color: 'var(--color-text-secondary)',
              marginBottom: '0.4rem',
            }}>
              Operator Email
            </label>
            <div style={{ position: 'relative' }}>
              <Mail size={16} color="var(--color-text-muted)" style={{
                position: 'absolute',
                left: '0.85rem',
                top: '50%',
                transform: 'translateY(-50%)',
              }} />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@soclite.local"
                style={{
                  width: '100%',
                  padding: '0.65rem 0.85rem 0.65rem 2.5rem',
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  fontSize: '0.88rem',
                  fontFamily: 'var(--font-sans)',
                  outline: 'none',
                  transition: 'border-color 0.2s',
                }}
                onFocus={(e) => e.target.style.borderColor = 'var(--color-accent)'}
                onBlur={(e) => e.target.style.borderColor = 'var(--color-border)'}
              />
            </div>
          </div>

          {/* Password field */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{
              display: 'block',
              fontSize: '0.78rem',
              fontWeight: 500,
              color: 'var(--color-text-secondary)',
              marginBottom: '0.4rem',
            }}>
              Access Key / Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={16} color="var(--color-text-muted)" style={{
                position: 'absolute',
                left: '0.85rem',
                top: '50%',
                transform: 'translateY(-50%)',
              }} />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                style={{
                  width: '100%',
                  padding: '0.65rem 2.5rem 0.65rem 2.5rem',
                  backgroundColor: 'var(--color-bg-surface)',
                  border: '1px solid var(--color-border)',
                  borderRadius: '6px',
                  color: 'var(--color-text-primary)',
                  fontSize: '0.88rem',
                  fontFamily: 'var(--font-sans)',
                  outline: 'none',
                  transition: 'border-color 0.2s',
                }}
                onFocus={(e) => e.target.style.borderColor = 'var(--color-accent)'}
                onBlur={(e) => e.target.style.borderColor = 'var(--color-border)'}
              />
              <button
                type="button"
                onClick={() => setShowPassword(p => !p)}
                style={{
                  position: 'absolute',
                  right: '0.75rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  color: 'var(--color-text-muted)',
                  padding: '0.2rem',
                }}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* Submit button */}
          <button
            type="submit"
            disabled={isSubmitting}
            style={{
              width: '100%',
              padding: '0.75rem',
              backgroundColor: isSubmitting ? 'var(--color-accent-dim)' : 'var(--color-accent)',
              color: '#080d14',
              border: 'none',
              borderRadius: '6px',
              fontSize: '0.88rem',
              fontWeight: 600,
              cursor: isSubmitting ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              transition: 'opacity 0.2s, transform 0.1s',
            }}
          >
            {isSubmitting ? (
              <span>Authenticating…</span>
            ) : (
              <>
                <span>Enter SOC Console</span>
                <ArrowRight size={16} />
              </>
            )}
          </button>
        </form>

        {/* Demo Quick-Fill Section */}
        <div style={{
          marginTop: '2rem',
          paddingTop: '1.25rem',
          borderTop: '1px solid var(--color-border-subtle)',
        }}>
          <div style={{
            fontSize: '0.72rem',
            color: 'var(--color-text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.08em',
            marginBottom: '0.75rem',
            textAlign: 'center',
          }}>
            Quick-Fill Demo Credentials
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem' }}>
            {DEMO_PRESETS.map((p) => {
              const active = email === p.email;
              return (
                <button
                  key={p.role}
                  type="button"
                  onClick={() => applyPreset(p)}
                  style={{
                    backgroundColor: active ? 'rgba(0, 212, 170, 0.12)' : 'var(--color-bg-surface)',
                    border: `1px solid ${active ? 'var(--color-accent)' : 'var(--color-border)'}`,
                    borderRadius: '6px',
                    padding: '0.45rem',
                    color: active ? 'var(--color-accent)' : 'var(--color-text-secondary)',
                    fontSize: '0.75rem',
                    fontWeight: 500,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.3rem',
                    transition: 'all 0.15s',
                  }}
                >
                  {active && <CheckCircle2 size={12} />}
                  <span>{p.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
