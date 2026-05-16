import { useEffect, useRef, useState } from 'preact/hooks';

export function TimelinePane({ onClose }) {
  const [events, setEvents] = useState([]);
  const [ebpf, setEbpf] = useState(false);
  const [filter, setFilter] = useState('');
  const lastSeenAt = useRef(0);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      const since = lastSeenAt.current ? `?since=${lastSeenAt.current}` : '';
      fetch(`/api/timeline${since}`)
        .then((r) => r.json())
        .then((d) => {
          if (cancelled) return;
          const fresh = d.events || [];
          if (fresh.length) {
            const maxAt = Math.max(...fresh.map((e) => e.at));
            // Use the newest event's timestamp + tiny epsilon as the next `since`.
            lastSeenAt.current = maxAt + 0.0001;
            setEvents((prev) => [...prev, ...fresh].slice(-2000));
          }
          setEbpf(!!d.ebpf_running);
        });
    };
    load();
    const t = setInterval(load, 2000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  const q = filter.trim().toLowerCase();
  const shown = q
    ? events.filter(
        (e) =>
          String(e.pid).includes(q) ||
          e.name.toLowerCase().includes(q) ||
          (e.cmd || '').toLowerCase().includes(q),
      )
    : events;

  return (
    <div class="timeline-pane">
      <div class="toolbar">
        <input
          placeholder="filter pid / name / cmd"
          value={filter}
          onInput={(e) => setFilter(e.currentTarget.value)}
        />
        <span class={`ebpf-pill${ebpf ? ' on' : ''}`} title="bpftrace subprocess status">
          eBPF: {ebpf ? 'on' : 'off'}
        </span>
        <button class="theme-btn" onClick={onClose}>
          ← tree
        </button>
      </div>
      <div class="timeline-list">
        {shown
          .slice()
          .reverse()
          .map((e, i) => (
            <div key={`${e.pid}-${e.at}-${i}`} class="timeline-row">
              <span class="ts">{new Date(e.at * 1000).toLocaleTimeString()}</span>
              <span class={`src ${e.source}`}>{e.source}</span>
              <span class="pid">#{e.pid}</span>
              <span class="name">{e.name}</span>
              <span class="cmd">{e.cmd || e.exe || ''}</span>
            </div>
          ))}
        {shown.length === 0 && <div class="empty">No events yet — exec something.</div>}
      </div>
    </div>
  );
}
