// App.jsx
import React from "react";
import { BrowserRouter as Router, Navigate, Route, Routes, useLocation } from "react-router-dom";

import Footer from "./components/footer.jsx";
import ProtectedRoute from "./components/ProtectedRoute.jsx";
import Login from "./pages/login.jsx";
import PhishingAnalyzer from "./pages/PhishingAnalyzer.jsx";

function AppRoutes() {
  const location = useLocation();
  const hideFooter = location.pathname === "/";
  return (
    <div className="app-shell d-flex flex-column min-vh-100">
      <div className="app-body flex-fill d-flex flex-column">
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/analyzer" element={<ProtectedRoute><PhishingAnalyzer /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/analyzer" replace />} />
        </Routes>
      </div>
      {!hideFooter && <Footer />}
    </div>
  );
}

function App() {
  return (
    <Router>
      <AppRoutes />
    </Router>
  );
}

export default App;
