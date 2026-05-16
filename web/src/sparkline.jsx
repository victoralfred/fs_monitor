// Minimal SVG sparkline. Takes an array of numbers and renders a polyline.
// Auto-scales to the data range. Width/height are fixed; the consumer wraps
// it in a flex container if it wants horizontal flexing.

export function Sparkline({ values, width = 120, height = 28, color = 'var(--accent)' }) {
  if (!values || values.length < 2) {
    return (
      <svg width={width} height={height} class="sparkline empty">
        <text
          x={width / 2}
          y={height / 2 + 4}
          text-anchor="middle"
          fill="var(--muted)"
          font-size="10"
        >
          —
        </text>
      </svg>
    );
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const step = width / (values.length - 1);
  const pts = values
    .map(
      (v, i) =>
        `${(i * step).toFixed(1)},${(height - ((v - min) / range) * (height - 2) - 1).toFixed(1)}`,
    )
    .join(' ');
  const last = values[values.length - 1];
  const lastY = height - ((last - min) / range) * (height - 2) - 1;
  return (
    <svg width={width} height={height} class="sparkline">
      <polyline points={pts} fill="none" stroke={color} stroke-width="1.5" />
      <circle cx={width} cy={lastY} r="2" fill={color} />
    </svg>
  );
}
