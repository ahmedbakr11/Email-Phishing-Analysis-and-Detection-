import api from "./axios";
import { apiBaseUrl } from "./axios";
import { encryptJsonPayload, resetEncryptionCache, } from "./encryption";

export const API_PATHS = {
  signup: "/auth/signup",
  login: "/auth/login",
  users: "/user/users",
};

export const parseApiError = (error) => {
  if (error.response?.data?.error) {
    return error.response.data.error;
  }
  if (error.response?.data?.message) {
    return error.response.data.message;
  }
  if (error.response?.data) {
    return JSON.stringify(error.response.data);
  }
  if (error.message === "Network Error") {
    return `Unable to reach the API at ${apiBaseUrl}. Make sure the backend is running and reachable.`;
  }
  if (error.message) {
    return error.message;
  }
  return "An unexpected error occurred";
};

export async function registerUser(userData) {
  let encryptedPayload;
  try {
    encryptedPayload = await encryptJsonPayload(userData);
  } catch (cryptoError) {
    console.error("Encryption setup failed:", cryptoError);
    throw new Error("Unable to secure signup request. Please refresh and retry.");
  }

  try {
    const response = await api.post(API_PATHS.signup, encryptedPayload);
    return response.data;
  } catch (error) {
    console.error("Registration failed:", error);
    const parsed = parseApiError(error);
    if (error.response?.status === 400 && /decrypt/i.test(parsed)) {
      resetEncryptionCache();
    }
    throw new Error(parsed);
  }
}

export async function loginUser(credentials) {
  let encryptedPayload;
  try {
    encryptedPayload = await encryptJsonPayload(credentials);
  } catch (cryptoError) {
    console.error("Encryption setup failed:", cryptoError);
    throw new Error("Unable to secure login request. Please refresh and retry.");
  }

  try {
    const response = await api.post(API_PATHS.login, encryptedPayload);
    return response.data;
  } catch (error) {
    console.error("Login failed:", error);
    const parsed = parseApiError(error);
    if (error.response?.status === 400 && /decrypt/i.test(parsed)) {
      resetEncryptionCache();
    }
    throw new Error(parsed);
  }
}

export async function getAllUsers() {
  try {
    const response = await api.get(API_PATHS.users);
    return response.data;
  } catch (error) {
    console.error("Fetching users failed:", error);
    throw new Error(parseApiError(error));
  }
}

export async function getUserById(id) {
  try {
    const response = await api.get(`${API_PATHS.users}/${id}`);
    return response.data;
  } catch (error) {
    console.error(`Fetching user ${id} failed:`, error);
    throw new Error(parseApiError(error));
  }
}

export async function updateUser(id, data) {
  try {
    const response = await api.put(`${API_PATHS.users}/${id}`, data);
    return response.data;
  } catch (error) {
    console.error(`Updating user ${id} failed:`, error);
    throw new Error(parseApiError(error));
  }
}

export async function deleteUser(id) {
  try {
    const response = await api.delete(`${API_PATHS.users}/${id}`);
    return response.data;
  } catch (error) {
    console.error(`Deleting user ${id} failed:`, error);
    throw new Error(parseApiError(error));
  }
}

export { api };
