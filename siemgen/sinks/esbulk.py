"""Elasticsearch _bulk sink: backfill ECS documents into logs-<dataset>-default
   data streams with a controlled (backdated) @timestamp.

   Uses the `create` action (required for data streams). Data streams are regular
   (not TSDS) so backdated timestamps are accepted."""
from __future__ import annotations

import json

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EsBulkSink:
    kind = "es"

    def __init__(self, url: str, user: str, password: str,
                 ca_cert: str = "", verify: bool = False, batch: int = 1000) -> None:
        self.url = url.rstrip("/")
        self.batch = batch
        self.count = 0
        self.errors = 0
        self.first_error = None      # reason of the first rejected doc (for diagnosis)
        self._buf: list[tuple[str, dict]] = []
        self._s = requests.Session()
        self._s.auth = (user, password)
        self._s.verify = ca_cert if ca_cert else verify

    def write_doc(self, index: str, doc: dict) -> None:
        self._buf.append((index, doc))
        if len(self._buf) >= self.batch:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            return
        lines: list[str] = []
        for index, doc in self._buf:
            lines.append(json.dumps({"create": {"_index": index}}))
            lines.append(json.dumps(doc, default=str))
        body = "\n".join(lines) + "\n"
        r = self._s.post(
            f"{self.url}/_bulk",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            timeout=120,
        )
        r.raise_for_status()
        result = r.json()
        if result.get("errors"):
            for item in result.get("items", []):
                err = item.get("create", {}).get("error")
                if err:
                    self.errors += 1
                    if self.first_error is None:
                        self.first_error = err.get("reason", str(err))
        self.count += len(self._buf)
        self._buf.clear()

    def close(self) -> None:
        self.flush()
