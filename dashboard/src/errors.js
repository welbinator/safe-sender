/**
 * Sprint C6 F-60 — surface real server error messages to the UI.
 *
 * Axios errors can carry a backend-provided `detail` (FastAPI shape:
 * `{ "detail": "..." }`). Validation errors come through as an array of
 * `{ loc, msg, type }` — flatten into "field: msg, field: msg".
 *
 * Network errors with no response payload fall through to `fallback` so
 * the dashboard never renders "undefined" or "[object Object]".
 */
export function extractErrorMessage(err, fallback) {
  if (!err) return fallback;

  const detail = err?.response?.data?.detail;
  if (typeof detail === 'string' && detail.trim()) return detail;

  if (Array.isArray(detail)) {
    const parts = detail
      .map((d) => {
        if (typeof d?.msg !== 'string') return null;
        const field = Array.isArray(d?.loc) ? d.loc.filter((x) => x !== 'body').join('.') : '';
        return field ? `${field}: ${d.msg}` : d.msg;
      })
      .filter(Boolean);
    if (parts.length) return parts.join(', ');
  }

  // Real Error instances (from axios network failures, etc.) — only surface
  // if there's no response payload at all. Don't mix server detail w/ generic
  // axios noise.
  if (!err?.response && typeof err?.message === 'string' && err.message.trim()) {
    // Plain `Error` objects from user code go through here too; skip those —
    // their `.name` is "Error" with no `isAxiosError`. We want to bubble
    // network-style errors specifically.
    if (err.isAxiosError || err.name !== 'Error') return err.message;
  }

  return fallback;
}
