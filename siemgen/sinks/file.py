"""File sink: append native log lines to files (one handle per path).

Keeps per-file line and byte counters so the run manifest can report exactly what
was written (students compare these numbers with what their SIEM ingested)."""
from __future__ import annotations

from pathlib import Path


class FileSink:
    kind = "text"

    def __init__(self) -> None:
        self._fh: dict[str, object] = {}
        self.count = 0                      # write_line calls (logical records)
        self.lines: dict[str, int] = {}     # path -> physical lines written
        self.bytes: dict[str, int] = {}     # path -> bytes written

    def _handle(self, path: str):
        h = self._fh.get(path)
        if h is None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            h = open(path, "a", encoding="utf-8")
            self._fh[path] = h
            self.lines.setdefault(path, 0)
            self.bytes.setdefault(path, 0)
        return h

    def write_line(self, path: str, line: str) -> None:
        text = line.rstrip("\n") + "\n"
        self._handle(path).write(text)
        self.count += 1
        self.lines[path] += text.count("\n")
        self.bytes[path] += len(text.encode("utf-8"))

    def flush(self) -> None:
        for h in self._fh.values():
            h.flush()

    def close(self) -> None:
        for h in self._fh.values():
            h.close()
        self._fh.clear()
