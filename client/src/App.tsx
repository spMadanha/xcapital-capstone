import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import XCapitalDashboard from './components/Dashboard';
import LoginPage from './pages/Login';
import UserManagement from './pages/UserManagement';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:4000';

// 🔐 Role-based Auth wrapper
function PrivateRoute({
  children,
  allowedRoles,
}: {
  children: JSX.Element;
  allowedRoles?: string[];
}) {
  const token = localStorage.getItem('xcap_token');
  const user = JSON.parse(localStorage.getItem('xcap_user') || 'null');

  if (!token) return <Navigate to="/login" replace />;
  if (allowedRoles && (!user || !allowedRoles.includes(user.role)))
    return <Navigate to="/" replace />; // Redirect unauthorized users

  return children;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Route */}
        <Route path="/login" element={<LoginPage />} />

        {/* Protected Route: Dashboard (all logged-in users) */}
        <Route
          path="/"
          element={
            <PrivateRoute>
              <XCapitalDashboard />
            </PrivateRoute>
          }
        />

        {/* Admin-only page */}
        <Route
          path="/admin/users"
          element={
            <PrivateRoute allowedRoles={['admin']}>
              <UserManagement />
            </PrivateRoute>
          }
        />

        {/* Default/Fallback */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  );
}
