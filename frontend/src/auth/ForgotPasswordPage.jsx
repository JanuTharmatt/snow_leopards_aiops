/**
 * Forgot Password Page Component.
 * Dispatches password recovery link.
 */

import React, { useState } from 'react';
import { auth, sendPasswordResetEmail } from './firebase';

export default function ForgotPasswordPage({ saasApiBase = '' }) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);
  const [isError, setIsError] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setStatusMessage(null);

    try {
      // 1. Call backend reset endpoint
      const resp = await fetch(`${saasApiBase}/api/v1/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      const data = await resp.json();

      // 2. Also dispatch Firebase reset if configured
      try {
        await sendPasswordResetEmail(auth, email);
      } catch (fbErr) {
        console.info('Firebase reset email handled via backend.');
      }

      setIsError(false);
      setStatusMessage(data.message || 'Password reset link dispatched.');
    } catch (err) {
      setIsError(true);
      setStatusMessage('Could not dispatch reset email. Please verify address.');
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

        <div className="bg-white/80 backdrop-blur-xl border border-white/80 rounded-3xl p-8 shadow-2xl shadow-indigo-900/10">
          <div className="pb-5 mb-5 border-b border-slate-100">
            <h2 className="text-base font-bold text-slate-900">Reset Your Password</h2>
            <p className="text-xs text-slate-500">Enter your email to receive recovery instructions</p>
          </div>

          {statusMessage && (
            <div className={`mb-4 text-xs font-semibold p-3 rounded-xl border text-center ${
              isError ? 'bg-rose-50 text-rose-600 border-rose-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            }`}>
              {statusMessage}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-slate-700 mb-1.5 uppercase tracking-wider">Account Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="name@domain.com"
                className="w-full text-xs font-medium text-slate-800 rounded-xl px-3.5 py-3 border border-slate-200 bg-slate-50/60 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={loading}
                className="w-full text-white font-bold text-xs uppercase tracking-wider py-3.5 rounded-xl bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-700 hover:to-violet-700 shadow-lg shadow-indigo-500/25 transition-all transform hover:-translate-y-0.5 active:translate-y-0"
              >
                {loading ? 'Dispatching...' : 'Send Recovery Link →'}
              </button>
            </div>
          </form>

          <div className="mt-4 text-center">
            <a href="/login" className="text-xs text-indigo-600 font-bold hover:underline">← Back to Console Login</a>
          </div>
        </div>

      </div>
    </div>
  );
}
