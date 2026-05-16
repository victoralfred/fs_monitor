import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useProcRow } from './main.jsx';
import { Sparkline } from './sparkline.jsx';

const FLAG_LABELS = {
  exe_suspicious_path: 'Executable in suspicious path',
  exe_deleted: 'Executable deleted (unlinked while running)',
  exe_memfd: 'Executable is memory-resident (memfd)',
  kthread_impersonation: 'Process impersonates a kernel thread',
  argv_exe_mismatch: 'argv[0] does not match exe (possible masquerade)',
  dangerous_env: 'Dangerous environment variable set (LD_PRELOAD / LD_AUDIT)',
  external_egress_from_suspicious: 'Suspicious-path exe is talking to the internet',
  fs_write_burst: 'Burst of file writes (possible overwrite payload)',
  fs_mass_delete: 'Mass file deletion (possible wiper)',
};

function SecurityTab({ flags }) {
  if (!flags.length) {
    return (
      <div style={{ color: 'var(--muted)' }}>
        No security indicators firing for this process. Indicators are unprivileged heuristics —
        absence is not proof of safety.
      </div>
    );
  }
  return (
    <table class="fds">
      <thead>
        <tr>
          <th style={{ width: 250 }}>indicator</th>
          <th style={{ width: 70 }}>severity</th>
          <th>evidence</th>
        </tr>
      </thead>
      <tbody>
        {flags.map((f, i) => (
          <tr key={i}>
            <td>{FLAG_LABELS[f.id] || f.id}</td>
            <td>
              <span class={`kind ${f.severity === 'high' ? 'deleted' : ''}`}>{f.severity}</span>
            </td>
            <td>{f.evidence}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function Detail({ pid }) {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState('overview');
  const [fdFilter, setFdFilter] = useState('');
  const [libFilter, setLibFilter] = useState('');
  const [env, setEnv] = useState(null);
  const [envCount, setEnvCount] = useState(null);
  const [showEnv, setShowEnv] = useState(false);
  // Seeded by one history fetch on selection; appended via WS rows.
  const [history, setHistory] = useState([]);
  const [fetchError, setFetchError] = useState(null); // null | "not_found" | string
  const lastSampleAt = useRef(0);
  const [killState, setKillState] = useState({ sig: 'SIGTERM', confirming: false, msg: '' });

  // One fetch per pid selection. cpu/rss/status come from the ws stream;
  // fds/sockets/maps are static enough to revalidate only on user action.
  useEffect(() => {
    if (pid == null) {
      setData(null);
      setFetchError(null);
      return;
    }
    let cancelled = false;
    setFetchError(null);
    setData(null);
    fetch(`/api/processes/${pid}`)
      .then((r) => {
        if (r.status === 404) {
          if (!cancelled) setFetchError('not_found');
          return null;
        }
        if (!r.ok) {
          if (!cancelled) setFetchError(`http_${r.status}`);
          return null;
        }
        return r.json();
      })
      .then((d) => {
        if (!cancelled && d) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setFetchError(`network: ${e.message}`);
      });
    return () => {
      cancelled = true;
    };
  }, [pid]);

  // Seed sparklines from one history fetch on pid change. Subsequent
  // samples come from the WS stream — no further polling.
  useEffect(() => {
    if (pid == null) {
      setHistory([]);
      lastSampleAt.current = 0;
      return;
    }
    let cancelled = false;
    fetch(`/api/processes/${pid}/history`)
      .then((r) => (r.ok ? r.json() : { samples: [] }))
      .then((d) => {
        if (cancelled) return;
        const samples = d.samples || [];
        setHistory(samples);
        if (samples.length) lastSampleAt.current = samples[samples.length - 1].at;
      });
    return () => {
      cancelled = true;
    };
  }, [pid]);

  // Merge live ws updates into the static detail snapshot.
  const liveRow = useProcRow(pid);

  // Append a new sparkline sample whenever the live row changes.
  useEffect(() => {
    if (!liveRow) return;
    const at = Date.now() / 1000;
    if (at - lastSampleAt.current < 1.5) return; // avoid double-counting
    lastSampleAt.current = at;
    setHistory((prev) => {
      const next = [...prev, { at, cpu: liveRow.cpu, rss: liveRow.rss }];
      return next.length > 60 ? next.slice(-60) : next;
    });
  }, [liveRow?.cpu, liveRow?.rss]);
  const merged = useMemo(() => {
    if (!data) return null;
    if (!liveRow) return data;
    return {
      ...data,
      status: liveRow.status ?? data.status,
      cpu_percent: liveRow.cpu ?? data.cpu_percent,
      memory_rss: liveRow.rss ?? data.memory_rss,
    };
  }, [data, liveRow]);

  useEffect(() => {
    if (pid == null || tab !== 'env') return;
    fetch(`/api/processes/${pid}/env?show_env=${showEnv ? 1 : 0}`)
      .then((r) => (r.ok ? r.json() : { env: {}, count: 0 }))
      .then((d) => {
        setEnv(d.env);
        setEnvCount(d.count);
      });
  }, [pid, tab, showEnv]);

  const filteredFds = useMemo(() => {
    if (!data) return [];
    const q = fdFilter.trim().toLowerCase();
    if (!q) return data.fds;
    return data.fds.filter((f) => f.target.toLowerCase().includes(q) || f.kind.includes(q));
  }, [data, fdFilter]);

  const filteredLibs = useMemo(() => {
    if (!data || !data.maps) return [];
    const q = libFilter.trim().toLowerCase();
    if (!q) return data.maps;
    return data.maps.filter((m) => m.path.toLowerCase().includes(q));
  }, [data, libFilter]);

  if (pid == null) return <div class="empty">Select a process on the left.</div>;
  if (fetchError === 'not_found')
    return (
      <div class="empty">
        Process <strong>#{pid}</strong> has exited. It existed when the tree last refreshed but is
        gone now — pick another row.
      </div>
    );
  if (fetchError)
    return (
      <div class="empty">
        Failed to load process #{pid}: <code>{fetchError}</code>
      </div>
    );
  if (!data) return <div class="empty">Loading pid {pid}…</div>;

  const view = merged || data;
  const cpuSeries = history.map((s) => s.cpu);
  const rssSeries = history.map((s) => s.rss);

  const doKill = (sig) => {
    setKillState({ sig, confirming: false, msg: 'sending…' });
    fetch('/api/csrf')
      .then((r) => r.json())
      .then(({ csrf }) =>
        fetch(`/api/processes/${pid}/signal`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            signal: sig,
            csrf,
            expected_start: liveRow?.started ?? null,
          }),
        }),
      )
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) =>
        setKillState({
          sig,
          confirming: false,
          msg: ok ? `sent ${sig}` : `error: ${JSON.stringify(j.detail || j)}`,
        }),
      )
      .catch((e) => setKillState({ sig, confirming: false, msg: `network error: ${e.message}` }));
  };

  return (
    <div class="detail">
      <div class="detail-head">
        <h1>
          {view.name} <span style={{ color: 'var(--muted)' }}>#{view.pid}</span>
        </h1>
        <div class="sparks" title={`${history.length} samples`}>
          <div>
            <span class="spark-label">cpu</span>
            <Sparkline values={cpuSeries} />
          </div>
          <div>
            <span class="spark-label">rss</span>
            <Sparkline values={rssSeries} color="#a855f7" />
          </div>
        </div>
        <div class="kill-block">
          {killState.confirming ? (
            <>
              <span>Send {killState.sig}?</span>
              <button class="kill-btn confirm" onClick={() => doKill(killState.sig)}>
                yes
              </button>
              <button
                class="theme-btn"
                onClick={() => setKillState({ ...killState, confirming: false })}
              >
                no
              </button>
            </>
          ) : (
            <>
              <select
                value={killState.sig}
                onChange={(e) => setKillState({ ...killState, sig: e.currentTarget.value })}
              >
                {['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGKILL', 'SIGSTOP', 'SIGCONT'].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
              <button
                class="kill-btn"
                onClick={() => setKillState({ ...killState, confirming: true, msg: '' })}
              >
                send signal
              </button>
            </>
          )}
          {killState.msg && <div class="kill-msg">{killState.msg}</div>}
        </div>
      </div>
      <dl class="meta">
        <dt>user</dt>
        <dd>{view.username}</dd>
        <dt>status</dt>
        <dd>{view.status}</dd>
        <dt>ppid</dt>
        <dd>{view.ppid}</dd>
        <dt>threads</dt>
        <dd>{view.num_threads}</dd>
        <dt>fds</dt>
        <dd>{view.num_fds}</dd>
        <dt>cpu</dt>
        <dd>{view.cpu_percent.toFixed(1)}%</dd>
        <dt>rss</dt>
        <dd>{(view.memory_rss / 1024 / 1024).toFixed(1)} MB</dd>
        <dt>exe</dt>
        <dd>{view.exe || <em>—</em>}</dd>
        <dt>cwd</dt>
        <dd>{view.cwd || <em>—</em>}</dd>
        <dt>cmdline</dt>
        <dd>{(view.cmdline || []).join(' ') || <em>—</em>}</dd>
      </dl>

      <div class="tabs">
        {['overview', 'files', 'sockets', 'libs', 'env', 'security'].map((t) => (
          <button key={t} class={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
            {t}{' '}
            {t === 'files'
              ? `(${data.fds.length})`
              : t === 'sockets'
                ? `(${data.sockets.length})`
                : t === 'libs'
                  ? `(${(data.maps || []).length})`
                  : t === 'security'
                    ? (data.flag_detail || []).length > 0
                      ? `⚠ ${(data.flag_detail || []).length}`
                      : '✓'
                    : ''}
          </button>
        ))}
      </div>

      {tab === 'files' && (
        <>
          <input
            placeholder="filter path / kind"
            value={fdFilter}
            onInput={(e) => setFdFilter(e.currentTarget.value)}
            style={{ width: '100%', padding: 4, marginBottom: 6 }}
          />
          <table class="fds">
            <thead>
              <tr>
                <th>fd</th>
                <th>kind</th>
                <th>target / addr</th>
              </tr>
            </thead>
            <tbody>
              {filteredFds.map((f) => (
                <tr key={f.fd}>
                  <td>{f.fd}</td>
                  <td>
                    <span class={`kind ${f.kind}${f.deleted ? ' deleted' : ''}`}>
                      {f.kind}
                      {f.deleted ? ' (del)' : ''}
                    </span>
                  </td>
                  <td>
                    {f.addr ? (
                      <>
                        <span>{f.target}</span>{' '}
                        <span style={{ color: 'var(--muted)' }}>· {f.addr}</span>
                      </>
                    ) : (
                      f.target
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {tab === 'sockets' && (
        <table class="fds">
          <thead>
            <tr>
              <th>fd</th>
              <th>family</th>
              <th>type</th>
              <th>laddr</th>
              <th>raddr</th>
              <th>status</th>
            </tr>
          </thead>
          <tbody>
            {data.sockets.map((s, i) => (
              <tr key={i}>
                <td>{s.fd ?? '—'}</td>
                <td>{s.family}</td>
                <td>{s.type}</td>
                <td>{s.laddr || '—'}</td>
                <td>{s.raddr || '—'}</td>
                <td>{s.status || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {tab === 'libs' && (
        <>
          <input
            placeholder="filter library path"
            value={libFilter}
            onInput={(e) => setLibFilter(e.currentTarget.value)}
            style={{ width: '100%', padding: 4, marginBottom: 6 }}
          />
          <table class="fds">
            <thead>
              <tr>
                <th>path</th>
                <th style={{ width: 90 }}>size</th>
                <th style={{ width: 60 }}>exec</th>
              </tr>
            </thead>
            <tbody>
              {filteredLibs.map((m) => (
                <tr key={m.path}>
                  <td>
                    {m.path}
                    {m.deleted && (
                      <span class="kind deleted" style={{ marginLeft: 6 }}>
                        deleted
                      </span>
                    )}
                    {m.is_system === false && <span class="lib-nonsys">non-system</span>}
                  </td>
                  <td style={{ textAlign: 'right' }}>{formatBytes(m.size)}</td>
                  <td>{m.executable ? '✓' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {tab === 'env' && (
        <>
          <label style={{ display: 'block', marginBottom: 6 }}>
            <input
              type="checkbox"
              checked={showEnv}
              onChange={(e) => setShowEnv(e.currentTarget.checked)}
            />{' '}
            reveal env ({envCount ?? '?'} vars · secret-looking keys still redacted)
          </label>
          {!showEnv && (
            <div style={{ color: 'var(--muted)' }}>
              Env vars hidden by default — even the variable names. Tick the box above to reveal.
            </div>
          )}
          {showEnv && (
            <table class="fds">
              <tbody>
                {env &&
                  Object.entries(env).map(([k, v]) => (
                    <tr key={k}>
                      <td style={{ width: 180 }}>{k}</td>
                      <td>{v}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {tab === 'security' && <SecurityTab flags={data.flag_detail || []} />}

      {tab === 'overview' && (
        <div style={{ color: 'var(--muted)' }}>
          Switch to <strong>files</strong> or <strong>sockets</strong> for details.
        </div>
      )}
    </div>
  );
}
