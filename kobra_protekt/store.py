"""Historique et préférences — port de HistoryStore / Prefs (local, sur la machine)."""
from __future__ import annotations
import json
import os
import time

from .signatures import APP_DIR

HISTORY_PATH = os.path.join(APP_DIR, "history.json")
PREFS_PATH = os.path.join(APP_DIR, "prefs.json")
MAX_EVENTS = 500


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return default


def _save(path, data):
    os.makedirs(APP_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=0)
    os.replace(tmp, path)


class History:
    def __init__(self):
        self.events = _load(HISTORY_PATH, [])

    def add(self, action: str, title: str, detail: str = ""):
        self.events.insert(0, {"t": time.strftime("%Y-%m-%d %H:%M"),
                               "action": action, "title": title, "detail": detail})
        self.events = self.events[:MAX_EVENTS]
        _save(HISTORY_PATH, self.events)

    def clear(self):
        self.events = []
        _save(HISTORY_PATH, self.events)


class Prefs:
    def __init__(self):
        self.d = _load(PREFS_PATH, {})

    def get(self, k, default=""):
        return self.d.get(k, default)

    def set(self, k, v):
        self.d[k] = v
        _save(PREFS_PATH, self.d)
