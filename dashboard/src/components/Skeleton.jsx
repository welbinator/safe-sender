import styles from './Skeleton.module.css';

/**
 * Sprint C6 F-62 — generic skeleton primitives.
 *
 * Replaces ad-hoc "Loading…" text with shimmer blocks so the layout doesn't
 * jump when data arrives. Each primitive is a plain `<div>` styled by the
 * CSS module; no animation libs.
 *
 * Accessibility: each shell sets `role="status"` and `aria-busy="true"`,
 * with an off-screen "Loading…" label so screen readers still hear it.
 */

export function SkeletonLine({ width = '100%', height = '1em', className = '' }) {
  return (
    <span
      className={`${styles.line} ${className}`}
      style={{ width, height }}
      aria-hidden="true"
    />
  );
}

export function SkeletonCard({ label }) {
  return (
    <div className={styles.card} role="status" aria-busy="true" aria-label={label || 'Loading'}>
      <SkeletonLine width="60%" height="0.85rem" />
      <SkeletonLine width="40%" height="2.25rem" className={styles.cardValue} />
    </div>
  );
}

export function SkeletonStats() {
  return (
    <div className={styles.statsGrid} role="status" aria-busy="true" aria-label="Loading dashboard stats">
      <SkeletonCard />
      <SkeletonCard />
      <SkeletonCard />
      <span className={styles.srOnly}>Loading…</span>
    </div>
  );
}

export function SkeletonRows({ rows = 5, cols = 5 }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        <tr key={r} className={styles.skelRow} aria-hidden="true">
          {Array.from({ length: cols }).map((__, c) => (
            <td key={c}>
              <SkeletonLine width={`${50 + ((r * 7 + c * 13) % 40)}%`} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
