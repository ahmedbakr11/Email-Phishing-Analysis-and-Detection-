import React from "react";
import Footer from "../components/Footer.jsx";

const AppLayout = ({ children, hideFooter = false }) => (
  <div className="app-shell d-flex flex-column min-vh-100">
    <div className="app-body flex-fill d-flex flex-column">
      {children}
    </div>
    {!hideFooter && <Footer />}
  </div>
);

export default AppLayout;
