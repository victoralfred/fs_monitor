import { render } from 'preact';
import { createContext } from 'preact';
import { useContext, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { Tree } from './tree.jsx';
import { Detail } from './detail.jsx';
import { TimelinePane } from './timeline.jsx';
import { NetworkPane } from './network.jsx';
import { ErrorBoundary } from './error-boundary.jsx';
import { applyDiff, buildTree } from './tree-builder.js';
import './styles.css';

const NEW_MS = 2000;
const GONE_MS = 1500;
const EXEC_MS = 2500;

export const ProcStreamCtx = createContext(null);

function useProcStream() {
  const [procs, setProcs] = useState(new Map());
  const [recentNew, setRecentNew] = useState(new Set());
  const [recentGone, setRecentGone] = useState(new Map());
  const [recentExec, setRecentExec] = useState(new Set());
  const [lag, setLag] = useState(null);
  const pending = useRef(null);

  useEffect(() => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (pending.current) cancelAnimationFrame(pending.current);
      pending.current = requestAnimationFrame(() => {
        setProcs((prev) => {
          const { next, added, removed, execed } = applyDiff(prev, msg);
          if (added.size) {
            setRecentNew((s) => new Set([...s, ...added]));
            setTimeout(
              () =>
                setRecentNew((s) => {
                  const n = new Set(s);
                  for (const pid of added) n.delete(pid);
                  return n;
                }),
              NEW_MS,
            );
          }
          if (removed.size) {
            setRecentGone((m) => {
              const n = new Map(m);
              for (const [pid, p] of removed) n.set(pid, p);
              return n;
            });
            setTimeout(
              () =>
                setRecentGone((m) => {
                  const n = new Map(m);
                  for (const pid of removed.keys()) n.delete(pid);
                  return n;
                }),
              GONE_MS,
            );
          }
          if (execed.size) {
            setRecentExec((s) => new Set([...s, ...execed]));
            setTimeout(
              () =>
                setRecentExec((s) => {
                  const n = new Set(s);
                  for (const pid of execed) n.delete(pid);
                  return n;
                }),
              EXEC_MS,
            );
          }
          return next;
        });
      });
    };
    const t = setInterval(() => {
      fetch('/api/health')
        .then((r) => r.json())
        .then((d) => setLag(d.scanner_lag_ms));
    }, 3000);
    return () => {
      ws.close();
      clearInterval(t);
    };
  }, []);

  return { procs, recentNew, recentGone, recentExec, lag };
}

function useParanoidStatus() {
  const [state, setState] = useState({ enabled: false, hidden_pids: [] });
  useEffect(() => {
    let cancelled = false;
    const load = () =>
      fetch('/api/security/paranoid')
        .then((r) => r.json())
        .then((d) => {
          if (!cancelled) setState(d);
        })
        .catch(() => {});
    load();
    const t = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);
  return state;
}

// Lightweight hook for Detail: subscribe to the parent's proc map and
// derive the row for a single pid. Returns the latest row (including
// cpu/rss/status updates from ws diffs) or undefined if the pid is gone.
export function useProcRow(pid) {
  const ctx = useContext(ProcStreamCtx);
  if (!ctx || pid == null) return undefined;
  return ctx.procs.get(pid);
}

function App() {
  const stream = useProcStream();
  const paranoid = useParanoidStatus();
  const { procs, recentNew, recentGone, recentExec, lag } = stream;
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(null);
  const [showKthreads, setShowKthreads] = useState(false);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [pane, setPane] = useState('tree'); // 'tree' | 'timeline' | 'network'
  const [dark, setDark] = useState(() => localStorage.getItem('monitor.dark') === '1');
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    localStorage.setItem('monitor.dark', dark ? '1' : '0');
  }, [dark]);

  const visible = useMemo(() => {
    let m = procs;
    if (recentGone.size) {
      m = new Map(procs);
      for (const [pid, p] of recentGone) if (!m.has(pid)) m.set(pid, p);
    }
    if (!flaggedOnly) return m;
    // Keep flagged pids and their ancestors so the tree stays connected.
    const keep = new Set();
    for (const p of m.values()) {
      if (p.flags && p.flags.length) {
        let cur = p;
        while (cur && !keep.has(cur.pid)) {
          keep.add(cur.pid);
          cur = m.get(cur.ppid);
        }
      }
    }
    const filtered = new Map();
    for (const pid of keep) filtered.set(pid, m.get(pid));
    return filtered;
  }, [procs, recentGone, flaggedOnly]);

  const tree = useMemo(
    () => buildTree(visible, query, showKthreads),
    [visible, query, showKthreads],
  );

  return (
    <ProcStreamCtx.Provider value={stream}>
      {paranoid.enabled && paranoid.hidden_pids.length > 0 && (
        <div class="paranoid-banner">
          ⚠ Paranoid mode: <strong>{paranoid.hidden_pids.length}</strong> hidden pid
          {paranoid.hidden_pids.length === 1 ? '' : 's'} detected (responds to kill(0) but missing
          from /proc): {paranoid.hidden_pids.slice(0, 10).join(', ')}
          {paranoid.hidden_pids.length > 10 ? ', …' : ''}
        </div>
      )}
      <div class="layout">
        <div class="pane">
          {pane === 'timeline' ? (
            <TimelinePane onClose={() => setPane('tree')} />
          ) : pane === 'network' ? (
            <NetworkPane
              onClose={() => setPane('tree')}
              onSelect={(p) => {
                setSelected(p);
                setPane('tree');
              }}
            />
          ) : (
            <>
              <div class="toolbar">
                <input
                  placeholder="filter pid / name / user"
                  value={query}
                  onInput={(e) => setQuery(e.currentTarget.value)}
                />
                <label class="toggle" title="Show kernel threads (children of pid 2)">
                  <input
                    type="checkbox"
                    checked={showKthreads}
                    onChange={(e) => setShowKthreads(e.currentTarget.checked)}
                  />{' '}
                  kthreads
                </label>
                <label class="toggle" title="Show only processes with active security flags">
                  <input
                    type="checkbox"
                    checked={flaggedOnly}
                    onChange={(e) => setFlaggedOnly(e.currentTarget.checked)}
                  />{' '}
                  flagged only
                </label>
                <button
                  class="theme-btn"
                  onClick={() => setPane('timeline')}
                  title="Show exec timeline"
                >
                  ⏱
                </button>
                <button
                  class="theme-btn"
                  onClick={() => setPane('network')}
                  title="Show external network connections"
                >
                  🌐
                </button>
                <button
                  class="theme-btn"
                  onClick={() => setDark((d) => !d)}
                  title="Toggle dark mode"
                >
                  {dark ? '☀' : '☾'}
                </button>
                <span
                  class={`lag${lag != null && lag > 500 ? ' over' : ''}`}
                  title={
                    lag != null && lag > 500
                      ? `Scanner over 500 ms budget (${lag} ms)`
                      : 'Scan duration of last tick'
                  }
                >
                  {lag != null ? `${lag} ms` : '…'}
                </span>
              </div>
              <Tree
                tree={tree}
                recentNew={recentNew}
                recentGone={recentGone}
                recentExec={recentExec}
                selected={selected}
                onSelect={setSelected}
              />
            </>
          )}
        </div>
        <div class="pane">
          <Detail pid={selected} />
        </div>
      </div>
    </ProcStreamCtx.Provider>
  );
}

render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
  document.getElementById('app'),
);
