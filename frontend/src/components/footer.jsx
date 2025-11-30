// Footer.jsx
import React from "react";
import { NavLink } from "react-router-dom";
import logo from "../assets/logo.png";

function Footer() {
  return (
    <footer className="app-footer mt-auto">
      <div className="container-fluid py-1">
        <div className="d-flex align-items-center">
          <NavLink
            to="/analyzer"
            className={({ isActive }) => `navbar-brand ${isActive ? "active" : ""}`}
            style={{ textDecoration: "none" }}
          >
            <span className="d-inline-flex align-items-center">
              <img src={logo} alt="DefendX logo" className="me-2 brand-logo" />
              DefendX
            </span>
          </NavLink>
        </div>
      </div>
    </footer>
  );
}

export default Footer;
