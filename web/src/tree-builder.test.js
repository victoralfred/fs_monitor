import { describe, it, expect } from 'vitest';
import { buildTree, applyDiff } from './tree-builder.js';

const p = (pid, ppid, extra = {}) => ({
  pid,
  ppid,
  name: extra.name || `p${pid}`,
  user: extra.user || 'me',
  status: 'S',
  cpu: 0,
  rss: 0,
  started: 0,
  ...extra,
});

const mapOf = (...procs) => new Map(procs.map((x) => [x.pid, x]));

describe('buildTree', () => {
  it('builds a basic 3-level tree from flat ppid links', () => {
    const procs = mapOf(p(1, 0), p(10, 1), p(20, 1), p(100, 10));
    const tree = buildTree(procs, '', false);
    expect(tree).toHaveLength(1);
    expect(tree[0].pid).toBe(1);
    expect(tree[0].children.map((c) => c.pid)).toEqual([10, 20]);
    expect(tree[0].children[0].children[0].pid).toBe(100);
  });

  it('hides kernel threads by default and reveals them when asked', () => {
    const procs = mapOf(p(1, 0), p(2, 0, { name: 'kthreadd' }), p(7, 2, { name: 'ksoftirqd' }));
    const hidden = buildTree(procs, '', false);
    // pid 2 stays (so users still see "kthreads exist" via the marker), kids gone.
    const flat = JSON.stringify(hidden);
    expect(flat).toContain('"pid":1');
    expect(flat).not.toContain('"pid":7');

    const shown = buildTree(procs, '', true);
    expect(JSON.stringify(shown)).toContain('"pid":7');
  });

  it('keeps ancestors of matches when filtering', () => {
    const procs = mapOf(
      p(1, 0, { name: 'init' }),
      p(10, 1, { name: 'sshd' }),
      p(100, 10, { name: 'bash' }),
      p(200, 1, { name: 'cron' }),
    );
    const tree = buildTree(procs, 'bash', false);
    // Should keep init → sshd → bash, drop cron.
    expect(tree).toHaveLength(1);
    expect(tree[0].pid).toBe(1);
    expect(tree[0].children).toHaveLength(1);
    expect(tree[0].children[0].pid).toBe(10);
    expect(tree[0].children[0].children[0].pid).toBe(100);
  });

  it('matches by pid, name, and user', () => {
    const procs = mapOf(p(42, 1, { name: 'x', user: 'alice' }));
    expect(buildTree(procs, '42', false)).toHaveLength(1);
    expect(buildTree(procs, 'x', false)).toHaveLength(1);
    expect(buildTree(procs, 'ALICE', false)).toHaveLength(1);
    expect(buildTree(procs, 'nope', false)).toHaveLength(0);
  });

  it('treats ppid=0 and missing-parent as root', () => {
    // pid 99 has ppid 50 but no pid 50 in the map.
    const procs = mapOf(p(1, 0), p(99, 50));
    const tree = buildTree(procs, '', false);
    expect(tree.map((r) => r.pid).sort()).toEqual([1, 99]);
  });
});

describe('applyDiff', () => {
  it('replaces state on a snapshot message', () => {
    const prev = mapOf(p(1, 0));
    const { next } = applyDiff(prev, { type: 'snapshot', procs: [p(2, 0)] });
    expect([...next.keys()]).toEqual([2]);
  });

  it('handles added / removed / changed / execed', () => {
    const prev = mapOf(p(1, 0, { cpu: 1.0 }), p(2, 0));
    const msg = {
      type: 'diff',
      added: [p(3, 0)],
      removed: [2],
      changed: [p(1, 0, { cpu: 5.0 })],
      execed: [1],
    };
    const { next, added, removed, execed } = applyDiff(prev, msg);
    expect([...next.keys()].sort()).toEqual([1, 3]);
    expect(next.get(1).cpu).toBe(5.0);
    expect([...added]).toEqual([3]);
    expect([...removed.keys()]).toEqual([2]);
    expect([...execed]).toEqual([1]);
  });

  it('tombstones removed pids with their last-known data', () => {
    const original = p(7, 1, { name: 'doomed' });
    const prev = mapOf(original);
    const { removed } = applyDiff(prev, {
      type: 'diff',
      added: [],
      removed: [7],
      changed: [],
    });
    expect(removed.get(7).name).toBe('doomed');
  });
});
