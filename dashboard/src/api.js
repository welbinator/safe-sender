import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || '/api';

// Sprint B C13: cookies for auth. `withCredentials: true` makes the browser
// send the HttpOnly `session` cookie on every request. We no longer touch
// localStorage — XSS can no longer steal the JWT.
const api = axios.create({ baseURL: BASE_URL, withCredentials: true });

// Sprint C1 CSRF hotfix: every request carries a custom header. The backend
// requires this header on cookie-authenticated mutations (POST/PUT/PATCH/DELETE).
// Browsers refuse to attach custom headers cross-origin without a CORS
// preflight — which our backend doesn't grant to third-party origins — so a
// malicious site can't forge a state-changing request even while the user's
// session cookie is live.
api.interceptors.request.use((config) => {
  config.headers = config.headers || {};
  config.headers['X-Requested-With'] = 'sender-safety';
  return config;
});

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      // Cookie is expired/invalid. Send the user back to the login page.
      // Don't redirect during the initial /me probe — AuthContext handles that.
      if (!err.config?.url?.endsWith('/customers/me')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  }
);

export default api;

export const authGoogle = (idToken) => api.post('/auth/google', { id_token: idToken });
export const authLogout = () => api.post('/auth/logout');
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
