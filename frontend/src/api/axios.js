import axios from "axios";

const rawBaseUrl = import.meta.env?.VITE_API_URL || "http://localhost:5000/api";
const baseURL = rawBaseUrl.endsWith("/")
  ? rawBaseUrl.slice(0, -1)
  : rawBaseUrl;

const api = axios.create({ baseURL });

api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("access_token");
    if (token) {
      config.headers = { ...config.headers, Authorization: `Bearer ${token}` };
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export const apiBaseUrl = baseURL;
export default api;
