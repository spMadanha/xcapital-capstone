import { useState } from 'react';

export default function UserManagement() {
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('viewer');
  const [password, setPassword] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);

  const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:4000';
  const token = localStorage.getItem('xcap_token');

  async function createUser(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/api/admin/create-user`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ email, name, role, password }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to create user');

      setResponse('🎉 User created successfully!');
      setEmail('');
      setName('');
      setPassword('');
    } catch (err: any) {
      setResponse(`❌ ${err.message}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-6 text-white">
      <h2 className="text-2xl mb-4">Admin — Create New User</h2>

      <form onSubmit={createUser} className="space-y-4 max-w-md bg-gray-800 p-4 rounded-lg">
        {response && <div className="text-sm bg-gray-700 p-2 rounded">{response}</div>}

        <input
          type="email"
          placeholder="User Email"
          className="w-full p-2 bg-gray-700 border border-gray-600 rounded"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />

        <input
          type="text"
          placeholder="Full Name"
          className="w-full p-2 bg-gray-700 border border-gray-600 rounded"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        <select
          className="w-full p-2 bg-gray-700 border border-gray-600 rounded"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          <option value="viewer">Viewer</option>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>

        <input
          type="text"
          placeholder="Temporary Password"
          className="w-full p-2 bg-gray-700 border border-gray-600 rounded"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        <button
          type="submit"
          disabled={loading}
          className={`w-full py-2 rounded bg-blue-600 hover:bg-blue-700 transition ${
            loading ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          {loading ? 'Creating...' : 'Create User'}
        </button>
      </form>
    </div>
  );
}
