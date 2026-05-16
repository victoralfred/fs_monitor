import { useEffect, useState } from 'preact/hooks';

export function NetworkPane({ onClose, onSelect }) {
  const [conns, setConns] = useState([]);
  const [externalOnly, setExternalOnly] = useState(true);
  const [filter, setFilter] = useState('');
  const [lastScan, setLastScan] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      fetch(`/api/connections?external_only=${externalOnly ? 1 : 0}`)
        .then((r) => r.json())
        .then((d) => {
          if (cancelled) return;
          setConns(d.connections || []);
          setLastScan(d.last_scan_at || 0);
        });
    load();
    const t = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [externalOnly]);

  const q = filter.trim().toLowerCase();
  const shown = q
    ? conns.filter(
        (c) =>
          String(c.pid).includes(q) ||
          c.comm.toLowerCase().includes(q) ||
          c.raddr.toLowerCase().includes(q) ||
          (c.proto || '').includes(q),
      )
    : conns;

  const fmt = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString() : '—');
  const stale = lastScan > 0 ? Math.round(Date.now() / 1000 - lastScan) : null;

  return (
    <div class="timeline-pane">
      <div class="toolbar">
        <input
          placeholder="filter pid / name / remote / proto"
          value={filter}
          onInput={(e) => setFilter(e.currentTarget.value)}
        />
        <label class="toggle" title="Show only routable-internet remotes">
          <input
            type="checkbox"
            checked={externalOnly}
            onChange={(e) => setExternalOnly(e.currentTarget.checked)}
          />{' '}
          external only
        </label>
        <span class="lag" title={`Last scan ${stale ?? '?'} s ago`}>
          {conns.length} conn{conns.length === 1 ? '' : 's'}
        </span>
        <button class="theme-btn" onClick={onClose}>
          ← tree
        </button>
      </div>
      <div class="timeline-list">
        {shown.map((c, i) => (
          <div
            key={`${c.pid}-${c.raddr}-${c.proto}-${i}`}
            class="conn-row"
            onClick={() => onSelect && onSelect(c.pid)}
          >
            <span class={`src ${c.proto}`}>{c.proto}</span>
            <span class="pid">#{c.pid}</span>
            <span class="name">{c.comm}</span>
            <span class="addr">
              {c.laddr || '—'} → <strong>{c.raddr}</strong>
              {c.external && <span class="ext-pill">external</span>}
            </span>
            <span class="state">{c.state || ''}</span>
            <span class="ts" title={`first ${fmt(c.first_seen)}`}>
              last {fmt(c.last_seen)}
            </span>
          </div>
        ))}
        {shown.length === 0 && (
          <div class="empty">
            No {externalOnly ? 'external ' : ''}connections.
            {lastScan === 0 && ' (Network scanner has not run yet.)'}
          </div>
        )}
      </div>
    </div>
  );
}
