"""Minimal Ollama client for the LLM director.

Talks to a LOCAL Ollama server (no data leaves the environment — a hard project
constraint). Uses `format: json` + temperature 0 + a fixed seed so the model
returns a single, deterministic JSON decision. Any failure raises and the caller
falls back to the rules director.
"""
from __future__ import annotations

import json

import requests


class OllamaClient:
    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3.2:3b",
                 temperature: float = 0, timeout: float = 20):
        self.url = url.rstrip("/")
        self.model = model
        self.temperature = float(temperature)
        self.timeout = float(timeout)

    def available(self) -> bool:
        """True if the Ollama server answers (checked once at startup)."""
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=min(5.0, self.timeout))
            return r.ok
        except Exception:  # noqa: BLE001
            return False

    def decide_json(self, prompt: str) -> dict:
        """Send the prompt, parse the JSON object the model returns."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.temperature, "seed": 0},
        }
        r = requests.post(f"{self.url}/api/generate", json=payload, timeout=self.timeout)
        r.raise_for_status()
        text = r.json().get("response", "")
        return json.loads(text)
