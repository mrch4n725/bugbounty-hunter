"""Footprint profile system — controls scanner fingerprint on the wire."""

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import requests


@dataclass
class FootprintProfile:
    name: str = ""
    rps: float = 3.0
    delay_jitter: float = 0.2
    user_agent_rotation: bool = True
    header_randomization: bool = False
    connection_reuse: bool = True
    request_signing: bool | str = False
    ip_rotation_enabled: bool = False
    max_retries: int = 3


MODERN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]


class FootprintManager:
    BUILTIN_PROFILES: dict[str, FootprintProfile] = {
        "stealth": FootprintProfile(
            name="stealth", rps=0.5, delay_jitter=0.5,
            user_agent_rotation=True, header_randomization=True,
            connection_reuse=False, request_signing=False,
            ip_rotation_enabled=False, max_retries=1,
        ),
        "normal": FootprintProfile(
            name="normal", rps=3.0, delay_jitter=0.2,
            user_agent_rotation=True, header_randomization=False,
            connection_reuse=True, request_signing=False,
            ip_rotation_enabled=False, max_retries=3,
        ),
        "aggressive": FootprintProfile(
            name="aggressive", rps=10.0, delay_jitter=0.0,
            user_agent_rotation=False, header_randomization=False,
            connection_reuse=True, request_signing=False,
            ip_rotation_enabled=False, max_retries=5,
        ),
    }

    def __init__(self, config: dict):
        self.config = config
        self._lock = threading.Lock()
        self._current_ua_index = 0
        self._profiles: dict[str, FootprintProfile] = dict(self.BUILTIN_PROFILES)
        profile_name = config.get("footprint", "normal")
        if profile_name in self._profiles:
            self._active = self._profiles[profile_name]
        else:
            self._active = self.BUILTIN_PROFILES["normal"]

    def get_profile(self, name: str | None = None) -> FootprintProfile:
        with self._lock:
            if name is None:
                return self._active
            return self._profiles.get(name, self._active)

    def apply_to_session(self, session: requests.Session, profile: FootprintProfile,
                         target_domain: str) -> None:
        ua = self.select_user_agent(profile)
        session.headers.update({"User-Agent": ua})
        session.verify = self.config.get("verify_ssl", True)
        retries = requests.adapters.Retry(
            total=profile.max_retries,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        )
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retries,
            pool_connections=10 if profile.connection_reuse else 1,
            pool_maxsize=10 if profile.connection_reuse else 1,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        if profile.header_randomization:
            self._randomize_headers(session)

    def _randomize_headers(self, session: requests.Session) -> None:
        accepts = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "application/json, text/plain, */*",
        ]
        accepts_langs = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.8",
            "en;q=0.9",
        ]
        sec_ch_uas = [
            '"Chromium";v="125", "Google Chrome";v="125", "Not=A?Brand";v="99"',
            '"Chromium";v="124", "Google Chrome";v="124", "Not=A?Brand";v="99"',
            '"Firefox";v="126"',
        ]
        session.headers.update({
            "Accept": random.choice(accepts),
            "Accept-Language": random.choice(accepts_langs),
            "Sec-CH-UA": random.choice(sec_ch_uas) if random.random() > 0.3 else "",
        })
        if random.random() > 0.5:
            session.headers["Accept-Encoding"] = "gzip, deflate, br"
        else:
            session.headers["Accept-Encoding"] = "gzip, deflate"

    def select_user_agent(self, profile: FootprintProfile) -> str:
        if profile.user_agent_rotation:
            return random.choice(MODERN_USER_AGENTS)
        return MODERN_USER_AGENTS[0]

    def rotate_user_agent(self, session: requests.Session) -> None:
        with self._lock:
            self._current_ua_index = (self._current_ua_index + 1) % len(MODERN_USER_AGENTS)
            ua = MODERN_USER_AGENTS[self._current_ua_index]
        session.headers.update({"User-Agent": ua})

    def add_request_signing(self, session: requests.Session, profile: FootprintProfile,
                            scan_id: str) -> None:
        if not profile.request_signing:
            return
        template = profile.request_signing
        scanner_id = self.config.get("scanner_id", "bbhunter")
        formatted = template.format(version=scanner_id)
        session.headers["X-Scanner"] = formatted
        session.headers["X-Scanner-ID"] = scanner_id
        session.headers["X-Scan-ID"] = scan_id
        session.headers["X-Request-ID"] = f"req_{random.randint(100000, 999999)}"

    @staticmethod
    def jittered_delay(profile: FootprintProfile) -> float:
        delay = 1.0 / profile.rps if profile.rps > 0 else 1.0
        jitter_range = delay * profile.delay_jitter
        return delay + random.uniform(-jitter_range, jitter_range)
