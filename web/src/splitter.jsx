// Vertical drag handle between the tree pane and the detail pane.
// Listeners attach to `window` (not the handle) so the cursor leaving
// the 6px hit-target during a drag doesn't strand the operation.

import { useEffect, useRef } from 'preact/hooks';

export function Splitter({ onResize }) {
  const dragging = useRef(false);

  useEffect(() => {
    const onMove = (e) => {
      if (!dragging.current) return;
      e.preventDefault();
      onResize(e.clientX);
    };
    const onUp = () => {
      if (!dragging.current) return;
      dragging.current = false;
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    return () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
  }, [onResize]);

  return (
    <div
      class="splitter"
      role="separator"
      aria-orientation="vertical"
      title="Drag to resize"
      onMouseDown={(e) => {
        e.preventDefault();
        dragging.current = true;
        // Suppress text selection + show resize cursor everywhere while dragging.
        document.body.style.userSelect = 'none';
        document.body.style.cursor = 'col-resize';
      }}
    />
  );
}
