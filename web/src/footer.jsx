// Bottom-of-window nav. Three links, nothing more.
// The repo URL is hardcoded here because the alternative — reading it
// from package.json or a server-provided constant — is more plumbing
// than the value justifies for a single string.

const REPO_URL = 'https://github.com/victoralfred/fs_monitor';

export function Footer({ ebpfRunning }) {
  return (
    <footer class="footer">
      <span class="footer-brand">monitor</span>
      <a href="/docs" target="_blank" rel="noopener noreferrer">
        API docs
      </a>
      <a href={REPO_URL} target="_blank" rel="noopener noreferrer">
        repo
      </a>
      {ebpfRunning != null && (
        <span class={`footer-ebpf${ebpfRunning ? ' on' : ''}`}>
          eBPF: {ebpfRunning ? 'on' : 'off'}
        </span>
      )}
    </footer>
  );
}
