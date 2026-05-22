/**
 * F-59 — credentials must be scoped to our backend, not the axios instance.
 *
 * These tests exercise the request interceptor in isolation by mocking
 * window.location + import.meta.env and importing api.js fresh.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Force a known origin before importing api.js.
const ORIGIN = 'https://app.sendersafety.com';

async function loadApi({ baseUrl = '/api', origin = ORIGIN, cookie = '' } = {}) {
  vi.resetModules();
  // jsdom default origin is http://localhost — override.
  Object.defineProperty(window, 'location', {
    value: new URL(origin),
    writable: true,
  });
  Object.defineProperty(document, 'cookie', {
    value: cookie,
    writable: true,
    configurable: true,
  });
  vi.stubGlobal('import.meta', { env: { VITE_API_URL: baseUrl } });
  // Vitest's import.meta isn't stubbable; rely on default '/api'.
  const mod = await import('../api.js');
  return mod.default;
}

function fakeConfig(url) {
  return { url, headers: {} };
}

function getInterceptor(api) {
  // axios stores handlers in interceptors.request.handlers[].fulfilled
  const handlers = api.interceptors.request.handlers;
  const h = handlers.find((x) => x && x.fulfilled);
  return h.fulfilled;
}

describe('api.js F-59 credentials scoping', () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it('instance default has withCredentials=false', async () => {
    const api = await loadApi();
    expect(api.defaults.withCredentials).toBe(false);
  });

  it('relative URL → cookies on, CSRF header added', async () => {
    const api = await loadApi({ cookie: 'csrf_token=abc123' });
    const interceptor = getInterceptor(api);
    const cfg = interceptor(fakeConfig('/rules'));
    expect(cfg.withCredentials).toBe(true);
    expect(cfg.headers['X-CSRF-Token']).toBe('abc123');
  });

  it('absolute same-origin URL → cookies on', async () => {
    const api = await loadApi({ cookie: 'csrf_token=abc123' });
    const interceptor = getInterceptor(api);
    const cfg = interceptor(fakeConfig(`${ORIGIN}/api/rules`));
    expect(cfg.withCredentials).toBe(true);
    expect(cfg.headers['X-CSRF-Token']).toBe('abc123');
  });

  it('cross-origin URL → cookies OFF, no CSRF header', async () => {
    const api = await loadApi({ cookie: 'csrf_token=abc123' });
    const interceptor = getInterceptor(api);
    const cfg = interceptor(fakeConfig('https://evil.example.com/steal'));
    expect(cfg.withCredentials).toBe(false);
    expect(cfg.headers['X-CSRF-Token']).toBeUndefined();
  });

  it('cross-origin URL strips a pre-set CSRF header', async () => {
    const api = await loadApi({ cookie: 'csrf_token=abc123' });
    const interceptor = getInterceptor(api);
    const cfg = {
      url: 'https://evil.example.com/steal',
      headers: { 'X-CSRF-Token': 'leak-me' },
    };
    const out = interceptor(cfg);
    expect(out.withCredentials).toBe(false);
    expect(out.headers['X-CSRF-Token']).toBeUndefined();
  });

  it('missing URL (axios default → BASE_URL) → cookies on', async () => {
    const api = await loadApi({ cookie: 'csrf_token=abc123' });
    const interceptor = getInterceptor(api);
    const cfg = interceptor(fakeConfig(undefined));
    expect(cfg.withCredentials).toBe(true);
    expect(cfg.headers['X-CSRF-Token']).toBe('abc123');
  });

  it('no csrf cookie → cookies on but no header', async () => {
    const api = await loadApi({ cookie: '' });
    const interceptor = getInterceptor(api);
    const cfg = interceptor(fakeConfig('/logs'));
    expect(cfg.withCredentials).toBe(true);
    expect(cfg.headers['X-CSRF-Token']).toBeUndefined();
  });
});
