// Pure tree-construction logic, extracted so it can be unit-tested.

/**
 * Map a CPU% (0..100) to a background colour for the heat map.
 * Returns null below the noise floor so most rows stay un-tinted.
 *
 * Gradient runs yellow → orange → red. Alpha grows with intensity so
 * very-low CPU stays barely-visible and 50%+ is the maximum saturation
 * we'll show. Anything beyond 50% looks the same — at that point the
 * user knows it's a busy process, the exact shade adds nothing.
 */
export function cpuHeatColor(cpu) {
  if (!cpu || cpu < 1) return null;
  const intensity = Math.min(1, cpu / 50);
  const hue = 60 - intensity * 60; // 60deg=yellow → 0deg=red
  const alpha = 0.12 + intensity * 0.4;
  return `hsla(${hue}, 90%, 55%, ${alpha.toFixed(2)})`;
}

export function buildTree(procs, query, showKthreads) {
  const q = query.trim().toLowerCase();
  const match = (p) =>
    !q ||
    String(p.pid).includes(q) ||
    p.name.toLowerCase().includes(q) ||
    p.user.toLowerCase().includes(q);

  // Mark pid 2 (kthreadd) and its descendants as kernel threads.
  const isKthread = new Map();
  if (procs.has(2)) {
    isKthread.set(2, true);
    const queue = [2];
    while (queue.length) {
      const parent = queue.shift();
      for (const p of procs.values()) {
        if (p.ppid === parent && !isKthread.has(p.pid)) {
          isKthread.set(p.pid, true);
          queue.push(p.pid);
        }
      }
    }
  }
  const hideKthread = (pid) => !showKthreads && isKthread.has(pid) && pid !== 2;

  const childrenOf = new Map();
  for (const p of procs.values()) {
    if (hideKthread(p.pid)) continue;
    if (!childrenOf.has(p.ppid)) childrenOf.set(p.ppid, []);
    childrenOf.get(p.ppid).push(p);
  }
  for (const arr of childrenOf.values()) arr.sort((a, b) => a.pid - b.pid);

  const keep = new Set();
  if (q) {
    for (const p of procs.values()) {
      if (hideKthread(p.pid)) continue;
      if (match(p)) {
        let cur = p;
        while (cur) {
          if (keep.has(cur.pid)) break;
          keep.add(cur.pid);
          cur = procs.get(cur.ppid);
        }
      }
    }
  }

  const roots = [];
  for (const p of procs.values()) {
    if (hideKthread(p.pid)) continue;
    if (!procs.has(p.ppid) || p.ppid === 0) {
      if (!q || keep.has(p.pid)) roots.push(p);
    }
  }
  roots.sort((a, b) => a.pid - b.pid);

  const decorate = (p, depth) => ({
    ...p,
    depth,
    kthread: isKthread.has(p.pid),
    children: (childrenOf.get(p.pid) || [])
      .filter((c) => !q || keep.has(c.pid))
      .map((c) => decorate(c, depth + 1)),
  });

  return roots.map((r) => decorate(r, 0));
}

// Apply a single ws message to a Map<pid, proc>. Returns a NEW map plus
// sets of pids that were added / removed / execed during this apply.
export function applyDiff(prev, msg) {
  if (msg.type === 'snapshot') {
    const next = new Map();
    for (const p of msg.procs) next.set(p.pid, p);
    return { next, added: new Set(), removed: new Map(), execed: new Set() };
  }
  const next = new Map(prev);
  const added = new Set();
  const removed = new Map();
  for (const p of msg.added || []) {
    next.set(p.pid, p);
    added.add(p.pid);
  }
  for (const p of msg.changed || []) next.set(p.pid, p);
  for (const pid of msg.removed || []) {
    const last = prev.get(pid);
    if (last) removed.set(pid, last);
    next.delete(pid);
  }
  const execed = new Set(msg.execed || []);
  return { next, added, removed, execed };
}
