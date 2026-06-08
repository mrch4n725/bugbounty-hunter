"""OOBBackgroundPoller — daemon thread that polls OOB callbacks during the scan.

When a callback arrives, it immediately promotes the matching finding to VERIFIED
rather than waiting until the end of the scan (where a single poll() may miss it).
"""

import threading
import time
from typing import Any, Callable

from modules.utils import log, Colors, VerificationStage


class OOBBackgroundPoller(threading.Thread):
    """Poll OOB callbacks every *interval* seconds.

    Parameters
    ----------
    oob_framework : OOBDetectionFramework
        The shared OOB detection instance.
    promote_callback : Callable[[str], bool]
        Called with the finding fingerprint when a callback matches.
        Should return True if promotion succeeded.
    interval : float
        Seconds between polls (default 4.0).
    """

    def __init__(
        self,
        oob_framework: Any,
        promote_callback: Callable[[str], bool],
        interval: float = 4.0,
    ):
        super().__init__(daemon=True)
        self.oob = oob_framework
        self.promote = promote_callback
        self.interval = interval
        self._stopped = threading.Event()

    def run(self) -> None:
        if not self.oob or not self.oob.oob_host:
            return
        while not self._stopped.wait(self.interval):
            try:
                confirmed = self.oob.poll()
                for entry in confirmed:
                    self._match_and_promote(entry)
            except Exception:
                continue

    def stop(self, timeout: float = 2.0) -> None:
        self._stopped.set()
        if self.is_alive():
            self.join(timeout=timeout)

    def _match_and_promote(self, entry: dict) -> None:
        payload = entry.get("payload", "")
        url = entry.get("url", "")
        log(f"  [OOB] Callback received — promoting matching finding @ {url}",
            Colors.GREEN)
        self.promote(payload)
