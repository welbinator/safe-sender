import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_URL || '/api';

// F-59 — per-endpoint credentials, not global.
//
// Previously `withCredentials: true` was set on the shared axios instance,
// which meant ANY URL passed through this instance (a misrouted call, a
// future third-party hit) would attach the session+CSRF cookies. The fix:
//
//   1. Instance default is `withCredentials: false`.
//   2. A request interceptor flips it ON *only* when the resolved URL
//      targets our own backend (relative path, or absolute URL whose
//      origin matches BASE_URL's origin / the current page origin).
//   3. Same-origin SPA -> /api/* always qualifies. Cross-origin /api on a
//      separate host qualifies via the BASE_URL origin check. A typo or
//      future absolute URL to `https://3rdparty.example/...` will NOT
//      receive cookies, even if accidentally routed through `api`.
//
// This is "default deny, opt in per scope" for credentials.
const api = axios.create({ baseURL: BASE_URL, withCredentials: false });

// Resolve BASE_URL to an absolute origin once. If BASE_URL is relative
// (the common case: '/api'), the backend origin === the page origin.
const BACKEND_ORIGIN = (() => {
  try {
    return new URL(BASE_URL, window.location.origin).origin;
  } catch {
    return window.location.origin;
  }
})();

function isSameBackend(url) {
  if (!url) return true; // axios defaults to BASE_URL → trusted
  try {
    const resolved = new URL(url, BACKEND_ORIGIN);
    return resolved.origin === BACKEND_ORIGIN;
  } catch {
    // Couldn't parse — assume relative → trusted.
    return true;
  }
}

// Sprint C3 F-11: double-submit-cookie CSRF. The backend sets a non-HttpOnly
// `csrf_token` cookie at login (256-bit random). We read it here and mirror
// it into the X-CSRF-Token header on every request. A cross-origin attacker
// can neither read this cookie (Same-Origin Policy) nor guess the token, so
// they can't satisfy the backend's constant-time check even while the browser
// auto-sends the session cookie.
function readCookie(name) {
  const prefix = name + '=';
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return '';
}

api.interceptors.request.use((config) => {
  config.headers = config.headers || {};
  // F-59: opt in to credentials only for our backend.
  if (isSameBackend(config.url)) {
    config.withCredentials = true;
    const csrf = readCookie('csrf_token');
    if (csrf) {
      config.headers['X-CSRF-Token'] = csrf;
    }
  } else {
    // Belt-and-suspenders: even if a future caller passes a third-party
    // URL through this instance, no cookies, no CSRF header.
    config.withCredentials = false;
    delete config.headers['X-CSRF-Token'];
  }
  return config;
});

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      // F-41: don't bash the URL bar from inside the HTTP layer — that
      // throws away React state, causes a full reload, and races with the
      // initial /me probe. Emit an event; AuthContext listens, clears its
      // own state, and navigates via the router (or shows a re-login modal
      // later). Suppress for /me which AuthContext owns directly.
      if (!err.config?.url?.endsWith('/customers/me')) {
        window.dispatchEvent(new CustomEvent('auth:unauthorized'));
      }
    }
    return Promise.reject(err);
  }
);

export default api;

// F-57: authGoogle (POST /auth/google) removed from the API surface. The
// dashboard now uses the server-side OAuth redirect flow — sign-in is a plain
// <a href="/api/auth/google/start"> in Login.jsx. The backend POST endpoint
// is kept one release as a deprecation cushion but no SPA code calls it.
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
export const getTestConnectionStatus = (testId) =>
  api.get(`/customers/test-connection/${testId}`);

// Sprint 7 — SMTP credentials
export const getSmtpCredentials = () => api.get('/customers/me/smtp-credentials');
export const rotateSmtpCredentials = () => api.post('/customers/me/smtp-credentials/rotate');

// Multi-domain management
export const getDomains = () => api.get('/customers/domains');
export const addDomain = (domain) => api.post('/customers/domains', { domain });
export const domainVerifyInit = (domain) => api.post(`/customers/domains/${encodeURIComponent(domain)}/verify/init`);
export const domainVerifyCheck = (domain) => api.post(`/customers/domains/${encodeURIComponent(domain)}/verify/check`);
export const deleteDomain = (domain) => api.delete(`/customers/domains/${encodeURIComponent(domain)}`);
// AI Add-On — Sprint 3
export const getAiStatus = () => api.get('/ai/status');
export const getAiPolicies = () => api.get('/ai/policies');
export const createAiPolicy = (policy_text) => api.post('/ai/policies', { policy_text });
export const deleteAiPolicy = (id) => api.delete(`/ai/policies/${id}`);
export const enableAiScan = () => api.post('/ai/enable');
export const disableAiScan = () => api.post('/ai/disable');
