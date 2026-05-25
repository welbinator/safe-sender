/**
 * Sentry initialization for the dashboard (React SPA).
 *
 * Reads from Vite env (must be prefixed VITE_ to be exposed to the bundle):
 *   VITE_SENTRY_DSN              — DSN URL. Unset/empty → no-op.
 *   VITE_SENTRY_ENVIRONMENT      — "production" | "staging" | "local". Default: "local".
 *   VITE_SENTRY_RELEASE          — git SHA injected at build time.
 *   VITE_SENTRY_TRACES_SAMPLE_RATE — float 0.0-1.0. Default 0.05.
 *
 * Privacy:
 *   - No PII attached automatically (Sentry's `sendDefaultPii: false`).
 *   - Network breadcrumbs strip Authorization headers via beforeBreadcrumb.
 *   - Avoid Replay for now — it can capture form inputs (auth, rule patterns).
 */
import * as Sentry from '@sentry/react';

const NOISY_URLS = ['/health', '/healthz', '/metrics'];
const EXPECTED_STATUS = new Set([401, 403, 404, 429]);

function beforeSend(event, hint) {
  // Drop noisy URLs.
  const url = event?.request?.url || '';
  if (NOISY_URLS.some((n) => url.endsWith(n))) return null;

  // Drop expected HTTP status errors thrown by axios/fetch wrappers.
  const status =
    hint?.originalException?.response?.status ??
    hint?.originalException?.status;
  if (status && EXPECTED_STATUS.has(status)) return null;

  // Strip Authorization header from request snapshot if present.
  if (event?.request?.headers) {
    delete event.request.headers.authorization;
    delete event.request.headers.Authorization;
    delete event.request.headers.cookie;
    delete event.request.headers.Cookie;
  }
  return event;
}

function beforeBreadcrumb(breadcrumb) {
  // Strip auth headers from fetch/xhr breadcrumbs.
  if (breadcrumb?.data?.request_headers) {
    delete breadcrumb.data.request_headers.authorization;
    delete breadcrumb.data.request_headers.Authorization;
  }
  return breadcrumb;
}

export function initSentry() {
  const dsn = import.meta.env.VITE_SENTRY_DSN;
  if (!dsn) {
    // eslint-disable-next-line no-console
    console.info('sentry: VITE_SENTRY_DSN unset, skipping init');
    return false;
  }

  const environment = import.meta.env.VITE_SENTRY_ENVIRONMENT || 'local';
  const release = import.meta.env.VITE_SENTRY_RELEASE || undefined;
  const tracesSampleRate = parseFloat(
    import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE || '0.05'
  );

  Sentry.init({
    dsn,
    environment,
    release,
    tracesSampleRate: Number.isFinite(tracesSampleRate) ? tracesSampleRate : 0.05,
    sendDefaultPii: false,
    integrations: [Sentry.browserTracingIntegration()],
    beforeSend,
    beforeBreadcrumb,
  });
  Sentry.setTag('service', 'dashboard');
  return true;
}
