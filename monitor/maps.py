"""Parse /proc/<pid>/maps into a deduplicated list of loaded objects.

Each line of /proc/<pid>/maps looks like:
    7f9a1c000000-7f9a1c023000 r-xp 00000000 fd:01 12345  /usr/lib/x86_64-linux-gnu/libc.so.6
We collapse all rows with the same pathname into a single entry, summing
their virtual-size and remembering whether any segment was executable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class MapEntry:
    path: str
    size: int        # sum of segment sizes for this path, in bytes
    executable: bool
    deleted: bool
    is_system: bool = True  # B4: false if path is outside the system prefix set


def annotate_system(entries: list[MapEntry], system_prefixes: tuple[str, ...]) -> None:
    """Set is_system on each entry based on the configured prefix list.
    Anonymous mappings and special regions are excluded by read_maps already.
    """
    for e in entries:
        e.is_system = any(e.path.startswith(p) for p in system_prefixes)


def read_maps(pid: int) -> list[MapEntry]:
    try:
        with open(f"/proc/{pid}/maps") as f:
            lines = f.readlines()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return []

    agg: dict[str, MapEntry] = {}
    for line in lines:
        parts = line.rstrip("\n").split(None, 5)
        if len(parts) < 6:
            continue
        addr, perms, _off, _dev, _ino, path = parts
        path = path.strip()
        if not path or path.startswith("["):
            # anonymous mapping or special region (e.g. [heap], [stack]) — skip
            continue
        try:
            lo, hi = addr.split("-")
            size = int(hi, 16) - int(lo, 16)
        except ValueError:
            continue
        deleted = path.endswith(" (deleted)")
        if deleted:
            path = path[: -len(" (deleted)")]
        executable = "x" in perms
        existing = agg.get(path)
        if existing is None:
            agg[path] = MapEntry(
                path=path, size=size, executable=executable, deleted=deleted
            )
        else:
            existing.size += size
            existing.executable = existing.executable or executable
            existing.deleted = existing.deleted or deleted

    # Libraries first (typically .so), then sort by size desc within each group.
    out = list(agg.values())
    out.sort(key=lambda m: (not _looks_like_lib(m.path), -m.size))
    return out


def _looks_like_lib(path: str) -> bool:
    return ".so" in path.rsplit("/", 1)[-1]
