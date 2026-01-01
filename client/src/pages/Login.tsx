import { useState } from 'react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // 📝 Note: We keep this variable so the code structure looks professional
  const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:4000';

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');

    // --- PORTFOLIO BYPASS START ---
    // We simulate a small delay to make it look like a real network request
    setTimeout(() => {
      try {
        // ✅ We skip the fetch() call entirely to avoid ECONNREFUSED errors.
        // ✅ We manually store the "Success" data just like the API would.
        
        localStorage.setItem('xcap_token', 'demo-token-12345');
        localStorage.setItem('xcap_user', JSON.stringify({ 
          email: email, 
          role: 'admin',
          name: 'Portfolio Guest' 
        }));

        // ✅ Immediate redirect
        window.location.href = '/';
      } catch (err: any) {
        setError("An unexpected error occurred.");
      } finally {
        setLoading(false);
      }
    }, 800); 
    // --- PORTFOLIO BYPASS END ---
  }

  return (
    <div className="flex items-center justify-center h-screen bg-gray-900 text-white px-4">
      <form
        onSubmit={handleLogin}
        className="bg-gray-800 p-8 rounded-lg shadow-lg w-full max-w-md"
      >
        <div className="text-center mb-6">
          <img
            src="https://xcapitalgrp.com/wp-content/uploads/2024/09/xc-resized.png"
            alt="XCapital Logo"
            className="h-12 mx-auto mb-2"
          />
          <h1 className="text-xl font-bold">XCapital Login</h1>
          <p className="text-gray-400 text-sm mt-1">Multi-Cloud Compliance Platform</p>
        </div>

        {error && (
          <div className="bg-red-600 text-white text-sm p-2 rounded mb-4 text-center">
            {error}
          </div>
        )}

        <div className="mb-4">
          <label className="text-sm text-gray-300">Email</label>
          <input
            type="email"
            className="w-full p-2 mt-1 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
          />
        </div>

        <div className="mb-6">
          <label className="text-sm text-gray-300">Password</label>
          <input
            type="password"
            className="w-full p-2 mt-1 bg-gray-700 border border-gray-600 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="********"
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className={`w-full py-2 rounded text-white font-semibold transition 
            ${loading ? 'bg-gray-600 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
        >
          {loading ? 'Signing in…' : 'Login'}
        </button>

        <p className="text-center text-xs text-gray-500 mt-4 italic">
          Portfolio Demo Mode — use any email/password to enter
        </p>
      </form>
    </div>
  );
}
