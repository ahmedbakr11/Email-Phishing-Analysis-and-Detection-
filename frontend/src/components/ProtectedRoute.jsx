import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { ACCESS_TOKEN_KEY } from "../utils/constants.js";

const ProtectedRoute = ({ children }) => {
  const location = useLocation();
  const token = localStorage.getItem(ACCESS_TOKEN_KEY);

  if (!token) {
    return <Navigate to="/" replace state={{ from: location }} />;
  }

  return children;
};

export default ProtectedRoute;
