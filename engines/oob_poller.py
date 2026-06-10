"""OOBBackgroundPoller — daemon thread that polls OOB callbacks during the scan.

When a callback arrives, it immediately promotes the matching finding to VERIFIED
rather than waiting until the end of the scan (where a single poll() may miss it).

Supports exponential backoff, configurable duration/poll limits, and exposes
a clear termination reason for auditability.
"""

import threading
import time
from typing import Any, Callable

from modules.utils import log, Colors


class OOBBackgroundPoller(threading.Thread):
    """Poll OOB callbacks with exponential backoff and termination limits.

    Parameters
    ----------
    oob_framework : OOBDetectionFramework
        The shared OOB detection instance.
    promote_callback : Callable[[str], bool]
        Called with the finding fingerprint when a callback matches.
        Should return True if promotion succeeded.
    interval : float
        Seconds between polls (default 4.0).
    max_duration : float
        Maximum wall-clock seconds the poller should stay alive (default 300.0).
        Set to 0 for no limit.
    max_polls : int
        Maximum number of poll iterations before self-stopping (default 0 = no limit).
    initial_interval : float
        Starting interval for exponential backoff (default 2.0).
        Only used when *backoff* is True.
    max_interval : float
        Ceiling for exponential backoff (default 30.0).
        Only used when *backoff* is True.
    backoff : bool
        Whether to apply exponential backoff to the poll interval (default True).
        The interval doubles on each poll and is capped at *max_interval*.
    """

    def __init__(
        self,
        oob_framework: Any,
        promote_callback: Callable[[str], bool],
        interval: float = 4.0,
        max_duration: float = 300.0,
        max_polls: int = 0,
        initial_interval: float = 2.0,
        max_interval: float = 30.0,
        backoff: bool = True,
    ):
        super().__init__(daemon=True)
        self.oob = oob_framework
        self.promote = promote_callback
        self.interval = interval
        self.max_duration = max_duration
        self.max_polls = max_polls
        self.initial_interval = initial_interval
        self.max_interval = max_interval
        self.backoff = backoff

        self._stopped = threading.Event()
        self._callback_count = 0
        self._termination_reason: str | None = None
        self._poll_count = 0
        self._start_time: float | None = None

    @property
    def callback_count(self) -> int:
        return self._callback_count

    @property
    def termination_reason(self) -> str | None:
        return self._termination_reason

    def run(self) -> None:
        if not self.oob or not self.oob.oob_host:
            self._termination_reason = "no_oob_host"
            return

        self._start_time = time.monotonic()
        current_interval = self.initial_interval if self.backoff else self.interval

        while not self._stopped.is_set():
            # Wall-clock duration limit
            if self.max_duration > 0:
                elapsed = time.monotonic() - self._start_time
                if elapsed >= self.max_duration:
                    self._termination_reason = "max_duration_reached"
                    break

            # Poll-count limit
            if self.max_polls > 0 and self._poll_count >= self.max_polls:
                self._termination_reason = "max_polls_reached"
                break

            # Wait for the current interval — return True if _stopped was set
            if self._stopped.wait(current_interval):
                self._termination_reason = "stopped"
                break

            self._poll_count += 1
            try:
                confirmed = self.oob.poll()
                for entry in confirmed:
                    self._callback_count += 1
                    self._match_and_promote(entry)
                # Exponential backoff: double interval, capped at max_interval
                if self.backoff:
                    current_interval = min(current_interval * 2, self.max_interval)
            except Exception:
                continue

        if self._termination_reason is None:
            self._termination_reason = "completed"

    def stop(self, timeout: float = 2.0) -> None:
        self._stopped.set()
        if self.is_alive():
            self.join(timeout=timeout)
        if self._termination_reason is None:
            self._termination_reason = "stopped"

    def _match_and_promote(self, entry: dict) -> None:
        payload = entry.get("payload", "")
        url = entry.get("url", "")
        log(f"  [OOB] Callback received — promoting matching finding @ {url}",
            Colors.GREEN)
        self.promote(payload)
