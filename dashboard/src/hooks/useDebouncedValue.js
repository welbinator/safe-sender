import { useEffect, useState } from 'react';

/**
 * Sprint C6 F-61 — useDebouncedValue
 *
 * Returns a copy of `value` that only updates after `delay` ms of no
 * changes. Useful for keystroke-driven filters where you want to defer
 * a re-render or network call until the user stops typing.
 *
 *   const debouncedSender = useDebouncedValue(senderInput, 300);
 */
export function useDebouncedValue(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);

  return debounced;
}
