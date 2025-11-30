// Profile.jsx
import React, { useEffect, useState } from "react";
import Header from "../components/header.jsx";
import { getUserById, updateUser } from "../api/index.js";
import { USER_STORAGE_KEY, USER_UPDATED_EVENT } from "../utils/constants.js";

function Profile() {
  const [editing, setEditing] = useState(false);
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("user");
  const [userId, setUserId] = useState(null);
  const [saved, setSaved] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const canEdit = (role || "user").toLowerCase() === "admin"; // only admins may edit

  useEffect(() => {
    const stored = localStorage.getItem(USER_STORAGE_KEY);
    if (!stored) {
      setError("No user session found. Please log in again.");
      setLoading(false);
      return;
    }

    try {
      const parsed = JSON.parse(stored);
      if (!parsed?.id) {
        setError("Invalid user session. Please log in again.");
        setLoading(false);
        return;
      }

      setUserId(parsed.id);
      setRole(parsed.role || "user");
      setFullName(parsed.fullname || parsed.full_name || "");

      const loadUser = async () => {
        setLoading(true);
        try {
          const userData = await getUserById(parsed.id);
          setUsername(userData.username || "");
          setEmail(userData.email || "");
          setFullName(userData.fullname || parsed.fullname || userData.username || "");
          setError("");
        } catch (apiError) {
          setError(apiError.message || "Unable to load profile.");
        } finally {
          setLoading(false);
        }
      };

      loadUser();
    } catch (e) {
      setError("Unable to read profile data. Please log in again.");
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!canEdit && editing) {
      setEditing(false);
    }
  }, [canEdit, editing]); // keep non-admin users in read-only mode

  const handleToggleEdit = () => {
    if (!canEdit) {
      // Safety guard: ignore toggle attempts triggered outside the admin UI
      return;
    }
    setEditing((value) => !value);
    setSaved(false);
    setError("");
  };

  const handleSave = async (event) => {
    event.preventDefault();
    if (!canEdit) {
      // Edit form should never submit for normal users, but exit defensively
      setError("You do not have permission to edit this profile.");
      return;
    }

    const trimmed = {
      fullName: fullName.trim(),
      email: email.trim(),
      username: username.trim(),
    };

    if (!trimmed.fullName || !trimmed.email || !trimmed.username) {
      alert("Please fill out Full Name, Email, and Username.");
      return;
    }

    if (!userId) {
      setError("Missing user identifier. Please log in again.");
      return;
    }

    try {
      setError("");
      await updateUser(userId, {
        id: userId,
        username: trimmed.username,
        email: trimmed.email,
        fullname: trimmed.fullName,
      });

      const updatedUser = {
        id: userId,
        username: trimmed.username,
        role,
        fullname: trimmed.fullName,
      };
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(updatedUser));
      window.dispatchEvent(new Event(USER_UPDATED_EVENT));

      setFullName(trimmed.fullName);
      setSaved(true);
      setEditing(false);
      setTimeout(() => setSaved(false), 2000);
    } catch (apiError) {
      setError(apiError.message || "Failed to update profile. Please try again.");
    }
  };

  if (loading) {
    return (
      <>
        <Header />
        <main className="tool-page__content">
          <div className="container" style={{ maxWidth: 720 }}>
            <div className="login-card">
              <p>Loading profile...</p>
            </div>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      <Header />
      <main
        className="tool-page__content d-flex align-items-center justify-content-center"
        style={{ minHeight: "calc(100vh - 80px)" }} // approximate header height to vertically center card
      >
        <div
          className="container d-flex align-items-center justify-content-center py-5"
          style={{ maxWidth: 720 }}
        >
          <div className="login-card w-100">
            {error && (
              <div className="error-text" style={{ color: "#f87171", marginBottom: "0.75rem" }}>
                {error}
              </div>
            )}
            {saved && (
              <div className="success-message fade-in-up" style={{ marginBottom: "0.75rem" }}>
                Profile updated successfully.
              </div>
            )}
            <h2 className="login-title" style={{ marginBottom: "1rem" }}>Your Profile</h2>

            {!editing || !canEdit ? (
              <div className="login-form" style={{ gap: ".85rem" }}>
                <div>
                  <strong>Full Name:</strong>
                  <div>{fullName || "-"}</div>
                </div>
                <div>
                  <strong>Email:</strong>
                  <div>{email || "-"}</div>
                </div>
                <div>
                  <strong>Username:</strong>
                  <div>@{username || "-"}</div>
                </div>
                <div>
                  <strong>Role:</strong>
                  <div>{role?.toLowerCase() === "admin" ? "Admin" : "User"}</div>
                </div>
                {canEdit && (
                  <div className="d-flex" style={{ gap: ".5rem", marginTop: ".5rem" }}>
                    <button className="login-button" onClick={handleToggleEdit} type="button">
                      Edit
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <form className="login-form" onSubmit={handleSave}>
                <div className="login-field">
                  <label htmlFor="fullName">Full Name</label>
                  <input
                    id="fullName"
                    type="text"
                    className="login-input"
                    value={fullName}
                    onChange={(event) => setFullName(event.target.value)}
                    placeholder="Enter your full name"
                  />
                </div>
                <div className="login-field">
                  <label htmlFor="email">Email</label>
                  <input
                    id="email"
                    type="email"
                    className="login-input"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                    placeholder="Enter your email"
                  />
                </div>
                <div className="login-field">
                  <label htmlFor="username">Username</label>
                  <input
                    id="username"
                    type="text"
                    className="login-input"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    placeholder="Choose a username"
                  />
                </div>
                <div className="login-field">
                  <label>Role</label>
                  <input
                    type="text"
                    className="login-input"
                    value={role?.toLowerCase() === "admin" ? "Admin" : "User"}
                    readOnly
                  />
                </div>

                <div className="d-flex" style={{ gap: ".5rem", marginTop: ".5rem" }}>
                  <button type="submit" className="login-button">Save Changes</button>
                  <button type="button" className="btn btn-outline-secondary" onClick={handleToggleEdit}>
                    Cancel
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      </main>
    </>
  );
}

export default Profile;
