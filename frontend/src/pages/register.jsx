// register.jsx
import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { Form } from "react-bootstrap";
import logoLogin from "../assets/logo-login.png";
import { registerUser } from "../api/index.js";

function Register() {
  const navigate = useNavigate();
  const [serverMessage, setServerMessage] = useState("");
  const [serverError, setServerError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors, isSubmitting, isValid },
  } = useForm({ mode: "onChange" });

  const onSubmit = async (data) => {
    setServerMessage("");
    setServerError("");
    try {
      const payload = {
        username: data.username.trim(),
        email: data.email.trim(),
        password: data.password,
        fullname: data.fullName.trim(),
      };
      await registerUser(payload);
      setServerMessage("Registration successful! Redirecting to login...");
      reset();
      setTimeout(() => navigate("/"), 2000);
    } catch (error) {
      setServerError(error.message || "Registration failed. Please try again.");
    }
  };

  return (
    <div className="login-page">
      <div className="login-wrap login-foreground">
        <div className="login-brand">
          <img src={logoLogin} alt="DefendX logo" className="login-logo" />
        </div>
        <div className="login-card register-card">
          <h2 className="login-title">Create your account</h2>
          <Form className="login-form" onSubmit={handleSubmit(onSubmit)} noValidate>
            <Form.Group className="login-field" controlId="fullName">
              <Form.Label>Full Name</Form.Label>
              <Form.Control
                type="text"
                placeholder="Enter your full name"
                className="login-input"
                maxLength={50}
                {...register("fullName", {
                  required: true,
                  maxLength: 50,
                  pattern: /^[A-Za-z ]+$/,
                })}
              />
              {errors.fullName?.type === "required" && (
                <span className="error-text" style={{ color: "#f87171" }}>Full Name is required</span>
              )}
              {errors.fullName?.type === "pattern" && (
                <span className="error-text" style={{ color: "#f87171" }}>Use English letters and spaces only</span>
              )}
              {errors.fullName?.type === "maxLength" && (
                <span className="error-text" style={{ color: "#f87171" }}>Full Name cannot exceed 50 characters</span>
              )}
            </Form.Group>

            <Form.Group className="login-field" controlId="email">
              <Form.Label>Email</Form.Label>
              <Form.Control
                type="email"
                placeholder="Enter your email"
                className="login-input"
                maxLength={50}
                {...register("email", {
                  required: true,
                  maxLength: 50,
                  pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                })}
              />
              {errors.email?.type === "required" && (
                <span className="error-text" style={{ color: "#f87171" }}>Email is required</span>
              )}
              {errors.email?.type === "pattern" && (
                <span className="error-text" style={{ color: "#f87171" }}>Enter a valid email</span>
              )}
              {errors.email?.type === "maxLength" && (
                <span className="error-text" style={{ color: "#f87171" }}>Email cannot exceed 50 characters</span>
              )}
            </Form.Group>

            <Form.Group className="login-field" controlId="username">
              <Form.Label>Username</Form.Label>
              <Form.Control
                type="text"
                placeholder="Choose a username"
                className="login-input"
                maxLength={25}
                {...register("username", {
                  required: true,
                  maxLength: 25,
                  pattern: /^[A-Za-z][A-Za-z0-9_]*$/,
                })}
              />
              {errors.username?.type === "required" && (
                <span className="error-text" style={{ color: "#f87171" }}>Username is required</span>
              )}
              {errors.username?.type === "maxLength" && (
                <span className="error-text" style={{ color: "#f87171" }}>Username cannot exceed 25 characters</span>
              )}
              {errors.username?.type === "pattern" && (
                <span className="error-text" style={{ color: "#f87171" }}>Must start with a letter; Can include "_" or numbers only</span>
              )}
            </Form.Group>

            <Form.Group className="login-field" controlId="password">
              <Form.Label>Password</Form.Label>
              <div className="password-field">
                <Form.Control
                  type={showPassword ? "text" : "password"}
                  placeholder="Create a password"
                  className="login-input"
                  maxLength={16}
                  minLength={8}
                  {...register("password", { required: true, minLength: 8 })}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M3.53 2.47a.75.75 0 0 0-1.06 1.06l2.141 2.14C2.17 7.11 1.03 8.82.4 10.06a2.9 2.9 0 0 0 0 2.41C1.73 14.96 5.58 21 12 21a11.1 11.1 0 0 0 5.61-1.6l2.86 2.86a.75.75 0 0 0 1.06-1.06ZM12 19.5c-5.5 0-8.81-5.37-9.44-6.74a1.4 1.4 0 0 1 0-1.52 15.3 15.3 0 0 1 2.86-3.46l2.52 2.52a5 5 0 0 0 6.36 6.36l1.42 1.42A9.62 9.62 0 0 1 12 19.5Zm-.5-9.27 3.77 3.77a3.5 3.5 0 0 1-3.77-3.77Z" />
                      <path d="m17.22 13.72 3.31 3.31a16.3 16.3 0 0 0 3.07-4.56 2.9 2.9 0 0 0 0-2.41C21.93 9.04 18.22 3 12 3a10.9 10.9 0 0 0-3.75.68l1.2 1.2A9.42 9.42 0 0 1 12 4.5c5.49 0 8.8 5.37 9.43 6.73a1.4 1.4 0 0 1 0 1.54 14.7 14.7 0 0 1-2.21 3Z" />
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M12 4.5c5.49 0 8.8 5.37 9.43 6.73a1.4 1.4 0 0 1 0 1.54C20.8 14.63 17.5 19.5 12 19.5S3.19 14.63 2.57 12.77a1.4 1.4 0 0 1 0-1.54C3.2 9.87 6.5 4.5 12 4.5Zm0-1.5C5.58 3 1.73 9.04.4 10.94a2.9 2.9 0 0 0 0 2.41C1.73 14.96 5.58 21 12 21s10.27-6.04 11.6-7.65a2.9 2.9 0 0 0 0-2.41C22.27 9.04 18.42 3 12 3Z" />
                      <path d="M12 9a3 3 0 1 1-3 3 3 3 0 0 1 3-3Zm0-1.5A4.5 4.5 0 1 0 16.5 12 4.5 4.5 0 0 0 12 7.5Z" />
                    </svg>
                  )}
                </button>
              </div>
              {errors.password?.type === "required" && (
                <span className="error-text" style={{ color: "#f87171" }}>Password is required</span>
              )}
              {errors.password?.type === "minLength" && (
                <span className="error-text" style={{ color: "#f87171" }}>Password must be at least 8 characters</span>
              )}
            </Form.Group>

            <Form.Group className="login-field" controlId="confirmPassword">
              <Form.Label>Confirm Password</Form.Label>
              <div className="password-field">
                <Form.Control
                  type={showConfirmPassword ? "text" : "password"}
                  placeholder="Re-enter your password"
                  className="login-input"
                  maxLength={16}
                  minLength={8}
                  {...register("confirmPassword", {
                    required: true,
                    validate: (value) => value === watch("password"),
                  })}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowConfirmPassword((prev) => !prev)}
                  aria-label={showConfirmPassword ? "Hide confirm password" : "Show confirm password"}
                >
                  {showConfirmPassword ? (
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M3.53 2.47a.75.75 0 0 0-1.06 1.06l2.141 2.14C2.17 7.11 1.03 8.82.4 10.06a2.9 2.9 0 0 0 0 2.41C1.73 14.96 5.58 21 12 21a11.1 11.1 0 0 0 5.61-1.6l2.86 2.86a.75.75 0 0 0 1.06-1.06ZM12 19.5c-5.5 0-8.81-5.37-9.44-6.74a1.4 1.4 0 0 1 0-1.52 15.3 15.3 0 0 1 2.86-3.46l2.52 2.52a5 5 0 0 0 6.36 6.36l1.42 1.42A9.62 9.62 0 0 1 12 19.5Zm-.5-9.27 3.77 3.77a3.5 3.5 0 0 1-3.77-3.77Z" />
                      <path d="m17.22 13.72 3.31 3.31a16.3 16.3 0 0 0 3.07-4.56 2.9 2.9 0 0 0 0-2.41C21.93 9.04 18.22 3 12 3a10.9 10.9 0 0 0-3.75.68l1.2 1.2A9.42 9.42 0 0 1 12 4.5c5.49 0 8.8 5.37 9.43 6.73a1.4 1.4 0 0 1 0 1.54 14.7 14.7 0 0 1-2.21 3Z" />
                    </svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M12 4.5c5.49 0 8.8 5.37 9.43 6.73a1.4 1.4 0 0 1 0 1.54C20.8 14.63 17.5 19.5 12 19.5S3.19 14.63 2.57 12.77a1.4 1.4 0 0 1 0-1.54C3.2 9.87 6.5 4.5 12 4.5Zm0-1.5C5.58 3 1.73 9.04.4 10.94a2.9 2.9 0 0 0 0 2.41C1.73 14.96 5.58 21 12 21s10.27-6.04 11.6-7.65a2.9 2.9 0 0 0 0-2.41C22.27 9.04 18.42 3 12 3Z" />
                      <path d="M12 9a3 3 0 1 1-3 3 3 3 0 0 1 3-3Zm0-1.5A4.5 4.5 0 1 0 16.5 12 4.5 4.5 0 0 0 12 7.5Z" />
                    </svg>
                  )}
                </button>
              </div>
              {errors.confirmPassword?.type === "required" && (
                <span className="error-text" style={{ color: "#f87171" }}>Confirm Password is required</span>
              )}
              {errors.confirmPassword?.type === "validate" && (
                <span className="error-text" style={{ color: "#f87171" }}>Passwords must match</span>
              )}
            </Form.Group>

            <button
              type="submit"
              className="login-button"
              disabled={isSubmitting || !isValid}
            >
              {isSubmitting ? "Registering..." : "Register"}
            </button>
          </Form>

          {serverError && (
            <div className="error-text" style={{ color: "#f87171", marginTop: "0.75rem" }}>
              {serverError}
            </div>
          )}

          {serverMessage && (
            <div className="success-message success-inline fade-in-up" style={{ marginTop: "0.75rem" }}>
              {serverMessage}
            </div>
          )}

          <div style={{ marginTop: "0.75rem", fontSize: ".95rem", color: "#374151" }}>
            Already have an account?{" "}
            <Link to="/" style={{ color: "#0d9488", fontWeight: 600, textDecoration: "none" }}>
              Login here
            </Link>
            .
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;
