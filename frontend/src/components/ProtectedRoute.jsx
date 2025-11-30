import React from "react";
import { Navigate, useLocation } from "react-router-dom";

const ProtectedRoute = ({ children }) => {
  const location = useLocation();
  const token = localStorage.getItem("access_token");
  let role = "admin";
  try {
    const stored = localStorage.getItem("user");
    role = (JSON.parse(stored)?.role || role).toLowerCase();
  } catch {
    role = "admin";
  }

  if (!token || role !== "admin") {
    return <Navigate to="/" replace state={{ from: location }} />;
  }

  return children;
};

export default ProtectedRoute;
