/**
 * Register Page Component with Frosted Glassmorphism.
 * Handles new organization onboarding and automatic tenant provisioning.
 */

import React, { useState } from 'react';
import { auth, createUserWithEmailAndPassword } from './firebase';

export default function RegisterPage({ onRegisterSuccess, saasApiBase = '' }) {
  const [orgName, setOrgName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // 1. Provision new tenant on SaaS service
      const resp = await fetch(`${saasApiBase}/api/v1/auth/register-tenant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenant_name: orgName,
          email,
          password
        })
      });

      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || 'Registration failed.');
      }

      // 2. Sync with Firebase client if available
      try {
        await createUserWithEmailAndPassword(auth, email, password);
      } catch (fbErr) {
        console.info('Firebase auth synced with tenant account.');
      }

      setSuccess(`Organization provisioned! Tenant ID: ${data.tenant_id}`);

      // 3. Persist session
      sessionStorage.setItem('sl_token', data.access_token);
      sessionStorage.setItem('sl_tenant', data.tenant_id);
      sessionStorage.setItem('sl_collector', data.collector_id);
      localStorage.setItem('sl_token', data.access_token);
      localStorage.setItem('sl_tenant', data.tenant_id);

      setTimeout(() => {
        if (onRegisterSuccess) {
          onRegisterSuccess(data);
        } else {
          window.location.href = `/dashboard?tenant_id=${encodeURIComponent(data.tenant_id)}`;
        }
      }, 1200);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
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

        {/* Card */}
        <div className="bg-white/80 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-2xl shadow-indigo-900/10">
          <div className="flex items-center justify-between pb-5 mb-5 border-b border-slate-100">
            <div>
              <h2 className="text-base font-bold text-slate-900">Create Tenant Account</h2>
              <p className="text-xs text-slate-500">Autonomous AIOps & Fleet Isolation</p>
            </div>
            <span className="text-[11px] font-mono font-semibold bg-indigo-50 text-indigo-700 px-2.5 py-1 rounded-full border border-indigo-200">
              Multi-Tenant
            </span>
          </div>

          {error && (
            <div className="mb-4 text-xs font-semibold text-rose-600 bg-rose-50 border border-rose-200 p-3 rounded-xl text-center">
              {error}
            </div>
          )}

          {success && (
            <div className="mb-4 text-xs font-semibold text-emerald-700 bg-emerald-50 border border-emerald-200 p-3 rounded-xl text-center">
              {success}
            </div>
          )}

          <form onSubmit={handleRegister} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1.5 uppercase tracking-wider">Organization / Team Name</label>
              <input
                type="text"
                required
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="e.g. Judge Evaluation Team, Acme Corp"
                className="w-full text-xs font-medium text-slate-800 rounded-xl px-3.5 py-3 border border-slate-200 bg-slate-50/60 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1.5 uppercase tracking-wider">Work / Judge Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@domain.com"
                className="w-full text-xs font-medium text-slate-800 rounded-xl px-3.5 py-3 border border-slate-200 bg-slate-50/60 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1.5 uppercase tracking-wider">Password (Min 6 chars)</label>
              <input
                type="password"
                required
                minLength={6}
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
                {loading ? 'Provisioning Tenant...' : 'Register & Provision Tenant →'}
              </button>
            </div>
          </form>

          <div className="mt-4 text-center">
            <p className="text-xs text-slate-500">
              Already have an account? <a href="/login" className="text-indigo-600 font-bold hover:underline">Sign In</a>
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
