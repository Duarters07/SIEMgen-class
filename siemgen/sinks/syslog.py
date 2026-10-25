"""Syslog sink: send native lines over UDP/TCP (e.g. pfSense -> Logstash :5140)."""
from __future__ import annotations

import socket


class SyslogSink:
    kind = "text"

    def __init__(self, host: str = "127.0.0.1", port: int = 5140, proto: str = "udp") -> None:
        self.addr = (host, int(port))
        self.proto = proto
        self.count = 0
        if proto == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect(self.addr)
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def write_line(self, path: str, line: str) -> None:  # path ignored (kept for parity)
        data = (line.rstrip("\n") + "\n").encode("utf-8")
        if self.proto == "tcp":
            self._sock.sendall(data)
        else:
            self._sock.sendto(data, self.addr)
        self.count += 1

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self._sock.close()
