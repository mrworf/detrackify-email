"""Thread-safe cache for resolved URLs for the guard server."""
import threading
import time
import json
import os
import logging

class ResolveCache:
    """Thread-safe cache for resolved URLs."""

    def __init__(self, max_entries=4096, max_age_days=30, path=None):
        self.lock = threading.Lock()
        self.data = {}
        self.max_entries = max_entries
        self.max_age = max_age_days * 24 * 3600
        self.path = path
        if path and os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    self.data = json.load(fh)
            except Exception:
                logging.exception('Failed to load cache file')
                self.data = {}
        self.prune()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self.thread.start()

    def _maintenance_loop(self):
        while not self.stop.wait(24 * 3600):
            self.prune()
            self.save()

    def prune(self):
        now = time.time()
        with self.lock:
            keys = [k for k, v in self.data.items() if now - v.get('ts', 0) > self.max_age]
            for k in keys:
                self.data.pop(k, None)

    def get(self, key):
        with self.lock:
            return self.data.get(key)

    def set(self, key, url, title='', warning=None, block_reason=None):
        entry = {'url': url, 'title': title or '', 'ts': time.time()}
        if warning:
            entry['warning'] = warning
        if block_reason:
            entry['block'] = block_reason
        with self.lock:
            self.data[key] = entry
            if len(self.data) > self.max_entries:
                oldest = min(self.data.items(), key=lambda item: item[1]['ts'])[0]
                self.data.pop(oldest, None)

    def save(self):
        if not self.path:
            return
        try:
            with self.lock, open(self.path, 'w', encoding='utf-8') as fh:
                json.dump(self.data, fh)
        except Exception:
            logging.exception('Failed to save cache file')

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.save() 