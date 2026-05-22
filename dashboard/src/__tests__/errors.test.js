import { describe, it, expect } from 'vitest';
import { extractErrorMessage } from '../errors';

describe('extractErrorMessage', () => {
  it('returns plain string detail (FastAPI default)', () => {
    const err = { response: { data: { detail: 'Bad rule pattern' } } };
    expect(extractErrorMessage(err, 'fallback')).toBe('Bad rule pattern');
  });

  it('joins FastAPI 422 validation detail array', () => {
    const err = {
      response: {
        data: {
          detail: [
            { loc: ['body', 'pattern'], msg: 'field required', type: 'value_error.missing' },
            { loc: ['body', 'scope'], msg: 'value is not a valid enumeration member', type: 'type_error' },
          ],
        },
      },
    };
    const out = extractErrorMessage(err, 'fallback');
    expect(out).toContain('pattern');
    expect(out).toContain('field required');
    expect(out).toContain('scope');
  });

  it('falls back when no response payload', () => {
    expect(extractErrorMessage(new Error('boom'), 'Could not load')).toBe('Could not load');
  });

  it('falls back on null/undefined', () => {
    expect(extractErrorMessage(null, 'nope')).toBe('nope');
    expect(extractErrorMessage(undefined, 'nope')).toBe('nope');
  });

  it('uses err.message when no response.data', () => {
    expect(extractErrorMessage({ message: 'Network Error' }, 'fb')).toBe('Network Error');
  });
});
