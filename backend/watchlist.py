"""
Watchlist Monitor — Scheduled phishing monitoring for domains/URLs.
Runs background threads to periodically rescan watched URLs.
"""
import threading, time, json, os
from datetime import datetime, timezone
from typing import Dict, Any, List, Callable

WATCHLIST_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "watchlist.json")


class WatchlistMonitor:
    """
    Monitors a list of URLs on a schedule and raises alerts
    when risk scores change significantly.
    """

    def __init__(self, scan_db):
        self._db          = scan_db
        self._entries     = self._load()
        self._results     = []
        self._lock        = threading.Lock()
        self._thread      = None
        self._running     = False
        self._run_scan_fn = None  # set after app is ready

    def set_scan_fn(self, fn: Callable):
        self._run_scan_fn = fn

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def is_running(self) -> bool:
        return self._running and (self._thread.is_alive() if self._thread else False)

    def _loop(self):
        """Main background loop — checks each entry every minute."""
        while self._running:
            now = time.time()
            with self._lock:
                entries = list(self._entries.values())
            for entry in entries:
                next_check = entry.get("last_checked", 0) + entry.get("interval_seconds", 3600)
                if now >= next_check and self._run_scan_fn:
                    self._check_entry(entry)
            time.sleep(30)  # poll every 30 seconds

    def _check_entry(self, entry: Dict):
        url = entry["url"]
        try:
            result = self._run_scan_fn(url, {
                "check_ssl": True,
                "check_content": False,
                "check_threat_intel": False,
            })
            new_score    = result.get("risk_score", 0)
            prev_score   = entry.get("last_score", 0)
            score_change = abs(new_score - prev_score)
            alert        = score_change >= 20 or (new_score >= 65 and prev_score < 65)

            record = {
                "url":           url,
                "scan_id":       result.get("scan_id"),
                "score":         new_score,
                "prev_score":    prev_score,
                "level":         result.get("risk_level"),
                "classification":result.get("classification"),
                "score_change":  round(score_change, 1),
                "alert":         alert,
                "checked_at":    datetime.now(timezone.utc).isoformat(),
            }

            with self._lock:
                # Update entry
                self._entries[url]["last_checked"] = time.time()
                self._entries[url]["last_score"]   = new_score
                self._entries[url]["check_count"]  = entry.get("check_count", 0) + 1
                # Keep last 100 results
                self._results = ([record] + self._results)[:100]

            self._save()
        except Exception as e:
            with self._lock:
                if url in self._entries:
                    self._entries[url]["last_checked"] = time.time()
                    self._entries[url]["last_error"]   = str(e)[:80]

    def add(self, url: str, interval_minutes: int = 60) -> Dict:
        entry = {
            "url":              url,
            "added_at":         datetime.now(timezone.utc).isoformat(),
            "interval_seconds": interval_minutes * 60,
            "interval_minutes": interval_minutes,
            "last_checked":     0,
            "last_score":       None,
            "check_count":      0,
        }
        with self._lock:
            self._entries[url] = entry
        self._save()
        return entry

    def remove(self, url: str):
        with self._lock:
            self._entries.pop(url, None)
        self._save()

    def get_all(self) -> List[Dict]:
        with self._lock:
            return list(self._entries.values())

    def get_results(self) -> List[Dict]:
        with self._lock:
            return list(self._results)

    def _load(self) -> Dict:
        os.makedirs(os.path.dirname(WATCHLIST_FILE), exist_ok=True)
        if os.path.exists(WATCHLIST_FILE):
            try:
                with open(WATCHLIST_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        try:
            with open(WATCHLIST_FILE, "w") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass
