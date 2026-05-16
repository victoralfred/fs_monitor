import { useMemo, useRef, useState, useEffect } from 'preact/hooks';
import { cpuHeatColor } from './tree-builder.js';

const ROW_H = 22;

function flatten(nodes, expanded, out = []) {
  for (const n of nodes) {
    out.push(n);
    if (n.children.length && expanded.has(n.pid)) {
      flatten(n.children, expanded, out);
    }
  }
  return out;
}

export function Tree({ tree, recentNew, recentGone, recentExec, selected, onSelect }) {
  const [expanded, setExpanded] = useState(() => new Set());
  const [autoExpanded, setAutoExpanded] = useState(false);
  const scrollerRef = useRef(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(600);

  // Expand top level on first load.
  useEffect(() => {
    if (!autoExpanded && tree.length) {
      const next = new Set();
      for (const r of tree) next.add(r.pid);
      setExpanded(next);
      setAutoExpanded(true);
    }
  }, [tree, autoExpanded]);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const flat = useMemo(() => flatten(tree, expanded), [tree, expanded]);

  const start = Math.max(0, Math.floor(scrollTop / ROW_H) - 10);
  const end = Math.min(flat.length, Math.ceil((scrollTop + height) / ROW_H) + 10);
  const slice = flat.slice(start, end);

  const toggle = (pid) =>
    setExpanded((s) => {
      const n = new Set(s);
      n.has(pid) ? n.delete(pid) : n.add(pid);
      return n;
    });

  return (
    <div class="tree" ref={scrollerRef} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
      <div style={{ height: flat.length * ROW_H, position: 'relative' }}>
        {slice.map((n, i) => {
          const idx = start + i;
          const hasKids = n.children.length > 0;
          const open = expanded.has(n.pid);
          const isSel = selected === n.pid;
          const isNew = recentNew.has(n.pid);
          const isGone = recentGone && recentGone.has(n.pid);
          const isExec = recentExec && recentExec.has(n.pid);
          const cls = [
            'row',
            isSel ? 'sel' : '',
            isNew ? 'new' : '',
            isGone ? 'gone' : '',
            isExec ? 'exec' : '',
            n.kthread ? 'kthread' : '',
          ]
            .filter(Boolean)
            .join(' ');
          // CPU heat map — only tint rows that aren't already wearing a
          // state colour, otherwise we'd hide the new/gone/exec/sel cue.
          const heat = !isSel && !isNew && !isGone && !isExec ? cpuHeatColor(n.cpu) : null;
          return (
            <div
              key={n.pid}
              class={cls}
              style={{
                position: 'absolute',
                top: idx * ROW_H,
                left: 0,
                right: 0,
                height: ROW_H,
                paddingLeft: 6 + n.depth * 14,
                ...(heat ? { backgroundColor: heat } : {}),
              }}
              onClick={() => onSelect(n.pid)}
            >
              <span
                class="caret"
                onClick={(e) => {
                  e.stopPropagation();
                  if (hasKids) toggle(n.pid);
                }}
              >
                {hasKids ? (open ? '▾' : '▸') : ''}
              </span>
              {n.flags && n.flags.length > 0 ? (
                <span class="flag-dot" title={`security flags: ${n.flags.join(', ')}`}>
                  ●
                </span>
              ) : (
                <span class="flag-dot empty" />
              )}
              <span class="pid">{n.pid}</span>
              <span class="name">{n.name}</span>
              <span class="user">{n.user}</span>
              <span class="cpu">{n.cpu.toFixed(1)}%</span>
              <span class="rss">{(n.rss / 1024 / 1024).toFixed(1)}M</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
