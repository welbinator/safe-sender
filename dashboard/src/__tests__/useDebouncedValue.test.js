import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useDebouncedValue } from '../hooks/useDebouncedValue';

describe('useDebouncedValue', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('returns initial value immediately', () => {
    const { result } = renderHook(() => useDebouncedValue('hello', 300));
    expect(result.current).toBe('hello');
  });

  it('debounces rapid changes — only the last value lands', () => {
    const { result, rerender } = renderHook(({ v }) => useDebouncedValue(v, 300), {
      initialProps: { v: 'a' },
    });
    rerender({ v: 'ab' });
    rerender({ v: 'abc' });
    rerender({ v: 'abcd' });

    // Not yet — timer hasn't fired.
    expect(result.current).toBe('a');

    act(() => { vi.advanceTimersByTime(299); });
    expect(result.current).toBe('a');

    act(() => { vi.advanceTimersByTime(1); });
    expect(result.current).toBe('abcd');
  });

  it('resets the timer on each change', () => {
    const { result, rerender } = renderHook(({ v }) => useDebouncedValue(v, 300), {
      initialProps: { v: 'x' },
    });
    rerender({ v: 'xy' });
    act(() => { vi.advanceTimersByTime(200); });
    rerender({ v: 'xyz' });
    act(() => { vi.advanceTimersByTime(200); });
    // Still original — second rerender reset the timer.
    expect(result.current).toBe('x');
    act(() => { vi.advanceTimersByTime(100); });
    expect(result.current).toBe('xyz');
  });
});
