
import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({ baseURL: BASE_URL });

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export default api;

export const authGoogle = (idToken) => api.post('/auth/google', { id_token: idToken });
export const getMe = () => api.get('/customers/me');
export const getRules = () => api.get('/rules');
export const createRule = (data) => api.post('/rules', data);
export const updateRule = (id, data) => api.put(`/rules/${id}`, data);
export const deleteRule = (id) => api.delete(`/rules/${id}`);
export const getLogs = (params) => api.get('/logs', { params });

// Sprint 5 — onboarding
export const verifyDomainInit = () => api.post('/customers/verify-domain/init');
export const verifyDomainCheck = () => api.post('/customers/verify-domain/check');
export const testConnection = () => api.post('/customers/test-connection');

// Sprint 7 — SMTP credentials
export const getSmtpCredentials = () => api.get('/customers/me/smtp-credentials');
export const rotateSmtpCredentials = () => api.post('/customers/me/smtp-credentials/rotate');

