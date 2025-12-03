import React from "react";
import { BrowserRouter as Router, Navigate, Route, Routes, useLocation } from "react-router-dom";
import AppLayout from "../layouts/AppLayout.jsx";
import ProtectedRoute from "../components/ProtectedRoute.jsx";
import Login from "../pages/Login.jsx";
import Register from "../pages/Register.jsx";
import ToolPhishing from "../tools/1_email_analyzer/phishing_email_analyzer.jsx";

function AppRoutes() {
  const location = useLocation();
  const hideFooter = location.pathname === "/" || location.pathname === "/register";

  return (
    <AppLayout hideFooter={hideFooter}>
      <Routes>
        <Route path="/" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/phishing"
          element={(
            <ProtectedRoute>
              <ToolPhishing />
            </ProtectedRoute>
          )}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  );
}

const AppRouter = () => (
  <Router>
    <AppRoutes />
  </Router>
);

export default AppRouter;
