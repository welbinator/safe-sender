import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SkeletonLine, SkeletonRows, SkeletonStats } from '../components/Skeleton';

describe('Skeleton primitives', () => {
  it('SkeletonLine renders with aria-hidden so screen readers skip it', () => {
    const { container } = render(<SkeletonLine />);
    const el = container.querySelector('[aria-hidden="true"]');
    expect(el).not.toBeNull();
  });

  it('SkeletonRows renders the requested number of rows', () => {
    render(<table><tbody><SkeletonRows rows={4} cols={3} /></tbody></table>);
    // Each row uses role="row" implicitly; query by element.
    const rows = document.querySelectorAll('tbody tr');
    expect(rows.length).toBe(4);
    expect(rows[0].querySelectorAll('td').length).toBe(3);
  });

  it('SkeletonStats announces loading to screen readers', () => {
    const { container } = render(<SkeletonStats />);
    // Outer wrapper is the announceable region.
    const outer = container.firstChild;
    expect(outer).toHaveAttribute('role', 'status');
    expect(outer).toHaveAttribute('aria-busy', 'true');
    expect(outer).toHaveAttribute('aria-label', 'Loading dashboard stats');
  });
});
