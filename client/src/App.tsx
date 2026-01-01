import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import XCapitalDashboard from './components/Dashboard';
import LoginPage from './pages/Login';
import UserManagement from './pages/UserManagement';

// 🔐 Portfolio Demo Auth Wrapper
// This version bypasses all real checks to ensure your portfolio is always accessible.
function PrivateRoute({
  children,
  allowedRoles,
}: {
  children: JSX.Element;
  allowedRoles?: string[];
}) {
  // --- BYPASS START ---
  // We mock a token and an admin user so the app thinks it's logged in.
  const token = "portfolio-demo-mode"; 
  const user = { role: 'admin', name: 'Portfolio Guest' };
  // --- BYPASS END ---

  // Since we hardcoded the values above, these checks will now always pass.
  if (!token) return <Navigate to="/login" replace />;
  
  if (allowedRoles && (!user || !allowedRoles.includes(user.role))) {
    return <Navigate to="/" replace />;
  }

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

        {/* Default/Fallback: Always send them to the Dashboard */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </BrowserRouter>
  );
}
