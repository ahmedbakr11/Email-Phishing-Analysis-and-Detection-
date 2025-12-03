// Header.jsx
import React, { useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import logo from "../assets/logo.png";
import {
  ACCESS_TOKEN_KEY,
  REFRESH_TOKEN_KEY,
  USER_STORAGE_KEY,
  USER_UPDATED_EVENT,
} from "../utils/constants.js";

function Header() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);

  const loadUserFromStorage = () => {
    try {
      const raw = localStorage.getItem(USER_STORAGE_KEY);
      if (!raw) {
        setUser(null);
        return;
      }
      const parsed = JSON.parse(raw);
      if (parsed) {
        parsed.role = parsed.role || "user";
        parsed.fullname = parsed.fullname || parsed.full_name || "";
      }
      setUser(parsed);
    } catch {
      setUser(null);
    }
  };

  useEffect(() => {
    loadUserFromStorage();
    const onStorage = (e) => {
      if (
        !e ||
        e.key === USER_STORAGE_KEY ||
        e.key === ACCESS_TOKEN_KEY ||
        e.key === REFRESH_TOKEN_KEY
      ) {
        loadUserFromStorage();
      }
    };
    window.addEventListener("storage", onStorage);
    window.addEventListener(USER_UPDATED_EVENT, loadUserFromStorage);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(USER_UPDATED_EVENT, loadUserFromStorage);
    };
  }, []);

  const handleLogout = (e) => {
    e.preventDefault();
    try {
      localStorage.removeItem(ACCESS_TOKEN_KEY);
      localStorage.removeItem(REFRESH_TOKEN_KEY);
      localStorage.removeItem(USER_STORAGE_KEY);
    } catch {}
    setUser(null);
    window.dispatchEvent(new Event(USER_UPDATED_EVENT));
    navigate("/");
  };

  const displayName = user?.fullname?.trim() || user?.username || "guest";

  return (
    <nav className="navbar navbar-expand-lg navbar-dark app-navbar">
      <div className="container-fluid">
        <NavLink
          to="/phishing"
          className={({ isActive }) => `navbar-brand ${isActive ? "active" : ""}`}
        >
          <span className="d-inline-flex align-items-center">
            <img src={logo} alt="DefendX logo" className="me-2 brand-logo" />
            DefendX
          </span>
        </NavLink>
        <button
          className="navbar-toggler"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#mainNavbar"
          aria-controls="mainNavbar"
          aria-expanded="false"
          aria-label="Toggle navigation"
        >
          <span className="navbar-toggler-icon"></span>
        </button>

        <div className="collapse navbar-collapse" id="mainNavbar">
          <ul className="navbar-nav me-auto mb-2 mb-lg-0">
            <li className="nav-item">
              <NavLink to="/phishing" className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>Phishing Email Analyzer</NavLink>
            </li>
          </ul>
          <div className="d-flex align-items-center gap-3 ms-auto">
            <span className="nav-user__name">{`Welcome, ${displayName}`}</span>
            <button type="button" className="btn btn-outline-light btn-sm" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}

export default Header;
