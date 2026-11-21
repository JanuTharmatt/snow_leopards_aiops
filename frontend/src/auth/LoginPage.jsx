/**
 * Login Page Component with Frosted Glassmorphism Styling.
 * SNOW LEOPARDS Autonomous AIOps & Observability Cloud.
 */

import React, { useState } from 'react';
import { auth, signInWithEmailAndPassword } from './firebase';

export default function LoginPage({ onLoginSuccess, saasApiBase = '' }) {
  const [email, setEmail] = useState('admin@snowleopards.ai');
  const [password, setPassword] = useState('DemoPassword2026!');
  const [tenantId, setTenantId] = useState('TENANT-001');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // 1. Authenticate with SaaS Multi-Tenant Backend
      const resp = await fetch(`${saasApiBase}/api/v1/auth/login-tenant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || 'Authentication failed. Please check credentials.');
      }

      // 2. Sync session with Firebase Auth if available
      try {
        await signInWithEmailAndPassword(auth, email, password);
      } catch (fbErr) {
        console.info('Firebase auth synced with backend session token.');
      }

      // 3. Persist session tokens
      sessionStorage.setItem('sl_token', data.access_token);
      sessionStorage.setItem('sl_tenant', data.tenant_id);
      sessionStorage.setItem('sl_collector', data.collector_id);
      localStorage.setItem('sl_token', data.access_token);
      localStorage.setItem('sl_tenant', data.tenant_id);

      if (onLoginSuccess) {
        onLoginSuccess(data);
      } else {
        window.location.href = `/dashboard?tenant_id=${encodeURIComponent(data.tenant_id)}`;
      }
    } catch (err) {
      setError(err.message || 'Login failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleInstantDemo = () => {
    setEmail('admin@snowleopards.ai');
    setPassword('DemoPassword2026!');
    setTenantId('TENANT-001');
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-slate-100"
         style={{
           background: "radial-gradient(circle at 10% 20%, rgba(127, 95, 227, 0.12) 0%, transparent 40%), linear-gradient(135deg, #f8f9fe 0%, #edf0fa 50%, #e7ecf8 100%)"
         }}>
      <div className="w-full max-w-md">
        
        {/* Logo Card */}
        <div className="text-center mb-6">
          <div className="inline-block p-2 bg-white rounded-3xl shadow-xl shadow-indigo-500/10 border border-slate-100">
            <img src="/static/images/snow_leopard_logo.jpg" alt="SNOW LEOPARDS" className="h-28 w-auto mx-auto object-contain rounded-2xl" />
          </div>
        </div>

        {/* Frosted Glass Login Surface */}
        <div className="bg-white/80 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-2xl shadow-indigo-900/10">
          <div className="flex items-center justify-between pb-5 mb-5 border-b border-slate-100">
            <div>
              <h2 className="text-base font-bold text-slate-900">Sign in to Console</h2>
              <p className="text-xs text-slate-500">Access enterprise fleet & AI telemetry</p>
            </div>
            <span className="text-[11px] font-mono font-semibold bg-emerald-50 text-emerald-700 px-2.5 py-1 rounded-full border border-emerald-200">
              Fleet Online
            </span>
          </div>

          {error && (
            <div className="mb-4 text-xs font-semibold text-rose-600 bg-rose-50 border border-rose-200 p-3 rounded-xl text-center">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1.5 uppercase tracking-wider">User / Judge Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="judge@snowleopards.ai"
                className="w-full text-xs font-medium text-slate-800 rounded-xl px-3.5 py-3 border border-slate-200 bg-slate-50/60 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-bold text-slate-700 uppercase tracking-wider">Password</label>
                <a href="/forgot-password" className="text-[11px] font-semibold text-indigo-600 hover:underline">Forgot?</a>
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full text-xs font-medium text-slate-800 rounded-xl px-3.5 py-3 border border-slate-200 bg-slate-50/60 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
              />
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={loading}
                className="w-full text-white font-bold text-xs uppercase tracking-wider py-3.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-700 hover:to-violet-700 shadow-lg shadow-indigo-500/25 transition-all transform hover:-translate-y-0.5 active:translate-y-0"
              >
                {loading ? 'Authenticating...' : 'Launch Observability Console →'}
              </button>
            </div>
          </form>

          <div className="mt-4 text-center">
            <p className="text-xs text-slate-500">
              New organization? <a href="/register" className="text-indigo-600 font-bold hover:underline">Register Tenant</a>
            </p>
          </div>

          <div className="mt-4 pt-4 border-t border-slate-100">
            <button
              onClick={handleInstantDemo}
              type="button"
              className="w-full bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-semibold py-2.5 px-3 rounded-xl border border-slate-200 transition"
            >
              ⚡ Instant Evaluator Demo Access
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
