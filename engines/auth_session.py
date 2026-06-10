import logging
import re
import threading
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    pyjwt = None
    HAS_JWT = False

CSRF_INPUT_NAMES = ("csrf", "csrf_token", "_token", "authenticity_token")
CSRF_HEADER_NAMES = ("X-CSRF-Token", "X-CSRF-TOKEN")
CSRF_META_NAME = "csrf-token"
CSRF_HEADER_OUT = "X-CSRF-Token"
CSRF_PARAM_OUT = "csrf_token"


class RoleSession:
    """Internal state for a single role's authenticated session."""

    def __init__(
        self,
        session: requests.Session,
        login_sequence: list[dict] | None = None,
        health_check_url: str | None = None,
        token_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        scopes: str | None = None,
    ):
        self.session = session
        self.login_sequence: list[dict] = login_sequence or []
        self.health_check_url: str | None = health_check_url
        self.token_url: str | None = token_url
        self.client_id: str | None = client_id
        self.client_secret: str | None = client_secret
        self.scopes: str | None = scopes

        self.oauth_token: str | None = None
        self.refresh_token: str | None = None
        self.token_expiry: float = 0.0
        self.csrf_token: str | None = None

        self.created_at: float = time.time()
        self.last_health_check: float = 0.0
        self.health_check_interval: float = 300.0

        self.extracted_values: dict[str, str] = {}

    @property
    def age(self) -> float:
        return time.time() - self.created_at

    @property
    def is_expired(self) -> bool:
        if self.token_expiry > 0 and time.time() >= self.token_expiry:
            return True
        return False

    def check_jwt_expiry(self) -> bool:
        if self.oauth_token and HAS_JWT:
            try:
                unverified = pyjwt.decode(
                    self.oauth_token, options={"verify_signature": False}
                )
                exp = unverified.get("exp")
                if exp and time.time() >= exp:
                    return True
            except Exception:
                pass
        return False


class AuthSessionManager:
    """Multi-role authenticated session manager.

    Maintains separate ``requests.Session`` instances per role, handles
    OAuth token exchange, JWT refresh, CSRF extraction, and login
    sequence replay.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self._lock = threading.Lock()
        self._roles: dict[str, RoleSession] = {}
        self._health_thread: threading.Thread | None = None
        self._health_stop = threading.Event()
        self._default_session = requests.Session()

        self._oauth_token_url: str | None = self.config.get("oauth_token_url")
        self._oauth_client_id: str | None = self.config.get("oauth_client_id")
        self._oauth_client_secret: str | None = self.config.get("oauth_client_secret")
        self._oauth_scopes: str | None = self.config.get("oauth_scopes")

    # ── Public API ───────────────────────────────────────────────────────

    def register_role(
        self,
        role: str,
        login_sequence: list[dict] | None = None,
        health_check_url: str | None = None,
        token_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        scopes: str | None = None,
    ) -> None:
        """Configure a role with optional login sequence, health-check, and OAuth credentials."""
        token_url = token_url or self._oauth_token_url
        client_id = client_id or self._oauth_client_id
        client_secret = client_secret or self._oauth_client_secret
        scopes = scopes or self._oauth_scopes

        sess = self._build_session()
        rs = RoleSession(
            session=sess,
            login_sequence=login_sequence,
            health_check_url=health_check_url,
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
        )

        with self._lock:
            self._roles[role] = rs

        if token_url and client_id and client_secret:
            self._oauth_flow(rs)

    def get_session(self, role: str = "default") -> requests.Session:
        """Return the ``requests.Session`` for *role* (falls back to default)."""
        with self._lock:
            rs = self._roles.get(role)
        if rs is None:
            return self._default_session
        return rs.session

    def get(self, role: str, url: str, **kwargs: Any) -> requests.Response:
        """GET request for *role* with automatic auth / CSRF injection and token refresh."""
        rs = self._resolve_role(role)
        if rs is None:
            return self._default_session.get(url, **kwargs)

        self._maybe_refresh_token(rs)
        kwargs = self._inject_auth(rs, kwargs)
        kwargs = self._inject_csrf(rs, kwargs)
        resp = rs.session.get(url, **kwargs)
        self._extract_csrf(rs, resp)
        self._handle_401(rs, resp, "get", url, kwargs)
        return resp

    def post(self, role: str, url: str, **kwargs: Any) -> requests.Response:
        """POST request for *role* with automatic auth / CSRF injection and token refresh."""
        rs = self._resolve_role(role)
        if rs is None:
            return self._default_session.post(url, **kwargs)

        self._maybe_refresh_token(rs)
        kwargs = self._inject_auth(rs, kwargs)
        kwargs = self._inject_csrf(rs, kwargs)
        resp = rs.session.post(url, **kwargs)
        self._extract_csrf(rs, resp)
        self._handle_401(rs, resp, "post", url, kwargs)
        return resp

    def refresh_all(self) -> None:
        """Re-authenticate all configured roles."""
        with self._lock:
            roles = dict(self._roles)

        for role, rs in roles.items():
            self._replay_login(rs)
            if rs.token_url and rs.client_id and rs.client_secret:
                self._oauth_flow(rs)

    def close(self) -> None:
        """Shut down background health checks and close all sessions."""
        self._health_stop.set()
        if self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=5)

        with self._lock:
            for rs in self._roles.values():
                rs.session.close()
            self._default_session.close()
            self._roles.clear()

    # ── OAuth ────────────────────────────────────────────────────────────

    def _oauth_flow(self, rs: RoleSession) -> None:
        """Exchange client credentials for a bearer token via the OAuth token endpoint."""
        if not (rs.token_url and rs.client_id and rs.client_secret):
            return

        try:
            data: dict[str, str] = {
                "grant_type": "client_credentials",
                "client_id": rs.client_id,
                "client_secret": rs.client_secret,
            }
            if rs.scopes:
                data["scope"] = rs.scopes

            resp = requests.post(rs.token_url, data=data, timeout=30)
            if resp.status_code != 200:
                logger.warning("OAuth token exchange failed for %s: %s", rs.token_url, resp.status_code)
                return

            payload = resp.json()
            self._apply_token_response(rs, payload)

        except requests.RequestException as exc:
            logger.warning("OAuth request failed: %s", exc)

    def _apply_token_response(self, rs: RoleSession, payload: dict[str, Any]) -> None:
        """Store token(s) from an OAuth token-response payload and update session headers."""
        access_token = payload.get("access_token")
        if access_token:
            rs.oauth_token = access_token
            rs.session.headers.update({"Authorization": f"Bearer {access_token}"})

        refresh_tok = payload.get("refresh_token")
        if refresh_tok:
            rs.refresh_token = refresh_tok

        expires_in = payload.get("expires_in")
        if expires_in:
            rs.token_expiry = time.time() + int(expires_in)

    def _refresh_oauth_token(self, rs: RoleSession) -> None:
        """Use a refresh token to obtain a new access token."""
        if not (rs.token_url and rs.refresh_token):
            return

        try:
            data: dict[str, str] = {
                "grant_type": "refresh_token",
                "refresh_token": rs.refresh_token,
            }
            resp = requests.post(rs.token_url, data=data, timeout=30)
            if resp.status_code != 200:
                logger.warning("OAuth refresh failed for %s: %d", rs.token_url, resp.status_code)
                return

            payload = resp.json()
            self._apply_token_response(rs, payload)

        except requests.RequestException as exc:
            logger.warning("OAuth refresh request failed: %s", exc)

    # ── JWT ──────────────────────────────────────────────────────────────

    def _jwt_refresh(self, rs: RoleSession) -> None:
        """Exchange a JWT for a fresh token by hitting the refresh endpoint.

        The refresh endpoint is taken from ``rs.token_url``.  If the
        response contains a new ``access_token`` it is applied; otherwise
        the existing *Authorization* header is removed so the caller can
        retry without a stale token.
        """
        if not rs.token_url:
            rs.session.headers.pop("Authorization", None)
            return

        try:
            resp = rs.session.post(rs.token_url, timeout=30)
            if resp.status_code == 200:
                payload = resp.json()
                self._apply_token_response(rs, payload)
                return
        except requests.RequestException:
            pass

        rs.session.headers.pop("Authorization", None)

    # ── CSRF ─────────────────────────────────────────────────────────────

    def _extract_csrf(self, rs: RoleSession, response: requests.Response) -> None:
        """Scan a response for CSRF tokens and store them on the role session."""
        token: str | None = None

        # 1. Hidden input fields
        text = response.text or ""
        for name in CSRF_INPUT_NAMES:
            # <input ... name="csrf_token" value="..." />
            for pattern in (
                rf'<input[^>]*name\s*=\s*["\']{name}["\'][^>]*value\s*=\s*["\']([^"\']+)["\']',
                rf'<input[^>]*value\s*=\s*["\']([^"\']+)["\'][^>]*name\s*=\s*["\']{name}["\']',
            ):
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    token = m.group(1)
                    break
            if token:
                break

        if not token:
            # 2. Response headers
            for header in CSRF_HEADER_NAMES:
                val = response.headers.get(header)
                if val:
                    token = val
                    break

        if not token:
            # 3. Meta tags: <meta name="csrf-token" content="...">
            m = re.search(
                rf'<meta[^>]*name\s*=\s*["\']{CSRF_META_NAME}["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
                text,
                re.IGNORECASE,
            )
            if m:
                token = m.group(1)

        if token:
            rs.csrf_token = token

    def _inject_csrf(self, rs: RoleSession, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Add CSRF token to outgoing request headers and form data."""
        token = rs.csrf_token
        if not token:
            return kwargs

        headers = dict(kwargs.pop("headers", {}))
        headers[CSRF_HEADER_OUT] = token
        kwargs["headers"] = headers

        data = kwargs.pop("data", None)
        if data is not None and isinstance(data, dict):
            data = dict(data)
            if CSRF_PARAM_OUT not in data:
                data[CSRF_PARAM_OUT] = token
            kwargs["data"] = data

        return kwargs

    # ── Auth header injection ───────────────────────────────────────────

    def _inject_auth(self, rs: RoleSession, kwargs: dict[str, Any]) -> dict[str, Any]:
        """Add the current OAuth *Authorization* header if not already present."""
        if rs.oauth_token:
            headers = dict(kwargs.get("headers", {}))
            if "Authorization" not in headers:
                headers["Authorization"] = f"Bearer {rs.oauth_token}"
            kwargs["headers"] = headers
        return kwargs

    # ── Token refresh / 401 handling ──────────────────────────────────

    def _maybe_refresh_token(self, rs: RoleSession) -> None:
        """Check whether the current token is expired and refresh if necessary."""
        if rs.is_expired or rs.check_jwt_expiry():
            if rs.refresh_token:
                self._refresh_oauth_token(rs)
            else:
                self._jwt_refresh(rs)

    def _handle_401(
        self, rs: RoleSession, response: requests.Response,
        method: str, url: str, kwargs: dict[str, Any],
    ) -> requests.Response | None:
        """On a 401 response, attempt token refresh and retry the request once."""
        if response.status_code != 401:
            return None

        if rs.refresh_token:
            self._refresh_oauth_token(rs)
        else:
            self._jwt_refresh(rs)

        if not rs.oauth_token and not rs.session.headers.get("Authorization"):
            return None

        kwargs = self._inject_auth(rs, kwargs)
        kwargs = self._inject_csrf(rs, kwargs)

        if method == "post":
            retry_resp = rs.session.post(url, **kwargs)
        else:
            retry_resp = rs.session.get(url, **kwargs)

        self._extract_csrf(rs, retry_resp)
        return retry_resp

    # ── Login sequence replay ───────────────────────────────────────────

    def _replay_login(self, rs: RoleSession) -> None:
        """Replay the configured login sequence for a role.

        Each step in *login_sequence* is a ``dict`` with keys:
          - ``method`` (str, default ``"get"``)
          - ``url`` (str)
          - ``data`` (dict, optional)
          - ``headers`` (dict, optional)
          - ``extract_rules`` (list[dict], optional)

        An *extract_rule* is a ``dict`` with keys:
          - ``name`` (str) — variable name for ``{name}`` substitution
          - ``pattern`` (str) — regex with at least one capture group,
            or ``"css:#id"`` / ``"css:.class"`` shorthand (simple
            CSS-selector extraction from raw HTML)
        """
        for step in rs.login_sequence:
            method = step.get("method", "get").lower()
            raw_url = step.get("url", "")
            data = step.get("data")
            headers = step.get("headers")

            url = self._substitute(rs, raw_url)
            if isinstance(data, dict):
                data = {k: self._substitute(rs, v) for k, v in data.items()}
            if isinstance(headers, dict):
                headers = {k: self._substitute(rs, v) for k, v in headers.items()}

            try:
                if method == "post":
                    resp = rs.session.post(url, data=data or {}, headers=headers or {}, timeout=30)
                else:
                    resp = rs.session.get(url, headers=headers or {}, timeout=30)
            except requests.RequestException as exc:
                logger.warning("Login step failed (%s %s): %s", method.upper(), url, exc)
                continue

            self._extract_csrf(rs, resp)

            for rule in step.get("extract_rules", []):
                self._apply_extract_rule(rs, rule, resp.text)

            rs.session.cookies.update(resp.cookies)

    def _apply_extract_rule(self, rs: RoleSession, rule: dict[str, Any], html: str) -> None:
        """Apply a single extraction rule and store the result."""
        name = rule.get("name", "")
        raw_pattern: str = rule.get("pattern", "")

        if not name or not raw_pattern:
            return

        css_match = re.match(r"^css:(.+)$", raw_pattern.strip(), re.IGNORECASE)
        if css_match:
            selector = css_match.group(1).strip()
            if selector.startswith("#"):
                element_id = selector[1:]
                m = re.search(
                    r'<[^>]*?id\s*=\s*["\']' + re.escape(element_id) + r'["\'][^>]*?>([^<]*)',
                    html, re.IGNORECASE,
                )
                if m:
                    rs.extracted_values[name] = m.group(1).strip()
            elif selector.startswith("."):
                class_name = selector[1:]
                m = re.search(
                    r'<[^>]*?class\s*=\s*["\'][^"\']*?\b' + re.escape(class_name) + r'\b[^"\']*["\'][^>]*?>([^<]*)',
                    html, re.IGNORECASE,
                )
                if m:
                    rs.extracted_values[name] = m.group(1).strip()
            return

        m = re.search(raw_pattern, html)
        if m:
            rs.extracted_values[name] = m.group(1).strip()

    def _substitute(self, rs: RoleSession, template: str) -> str:
        """Replace ``{name}`` placeholders with previously extracted values."""
        def _replacer(m: re.Match) -> str:
            key = m.group(1)
            return rs.extracted_values.get(key, m.group(0))
        return re.sub(r"\{(\w+)\}", _replacer, template)

    # ── Health checks ────────────────────────────────────────────────────

    def start_health_checks(self, interval: float = 300.0) -> None:
        """Start a background thread that periodically validates all role sessions."""
        self._health_stop.clear()

        with self._lock:
            for rs in self._roles.values():
                rs.health_check_interval = interval

        if self._health_thread and self._health_thread.is_alive():
            return

        self._health_thread = threading.Thread(
            target=self._health_loop,
            daemon=True,
            name="auth-session-health",
        )
        self._health_thread.start()

    def stop_health_checks(self) -> None:
        """Stop the background health-check thread."""
        self._health_stop.set()
        if self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=5)
        self._health_thread = None

    def _health_loop(self) -> None:
        """Background loop that checks all role sessions periodically."""
        while not self._health_stop.is_set():
            now = time.time()
            with self._lock:
                roles_snapshot = list(self._roles.items())

            min_interval = 300.0
            for role, rs in roles_snapshot:
                if self._health_stop.is_set():
                    return
                if not rs.health_check_url:
                    continue
                if now - rs.last_health_check < rs.health_check_interval:
                    continue

                rs.last_health_check = now
                healthy = self._check_role_health(rs)
                if not healthy:
                    logger.info("Session expired for role '%s', replaying login", role)
                    self._replay_login(rs)
                    if rs.token_url and rs.client_id and rs.client_secret:
                        self._oauth_flow(rs)
                min_interval = min(min_interval, rs.health_check_interval)

            self._health_stop.wait(timeout=min(60.0, min_interval))

    def _check_role_health(self, rs: RoleSession) -> bool:
        """Verify a single role's session by calling its health-check endpoint."""
        if not rs.health_check_url:
            return True

        try:
            resp = rs.session.get(rs.health_check_url, timeout=15, allow_redirects=False)
            if resp.status_code in (200, 204, 302):
                return True
        except requests.RequestException:
            pass

        return False

    # ── Helpers ──────────────────────────────────────────────────────────

    def _resolve_role(self, role: str) -> RoleSession | None:
        """Thread-safe lookup of a role, returning ``None`` for unknown roles."""
        with self._lock:
            return self._roles.get(role)

    def _build_session(self) -> requests.Session:
        """Create a fresh ``requests.Session`` with optional proxy / verify config."""
        session = requests.Session()
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        })

        proxy = self.config.get("proxy")
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        session.verify = self.config.get("verify_ssl", True)

        return session

    def _token_from_basic_auth(self, role: str) -> str | None:
        """Extract a bearer token from a role session's *Authorization* header."""
        rs = self._resolve_role(role)
        if rs is None:
            return None
        auth = rs.session.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:]
        return None

    # ── Serialization helpers for config storage ─────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialize the current session state (tokens, CSRF, extracted values) to JSON-safe dict."""
        with self._lock:
            roles_data: dict[str, Any] = {}
            for role, rs in self._roles.items():
                roles_data[role] = {
                    "oauth_token": rs.oauth_token,
                    "refresh_token": rs.refresh_token,
                    "token_expiry": rs.token_expiry,
                    "csrf_token": rs.csrf_token,
                    "created_at": rs.created_at,
                    "extracted_values": dict(rs.extracted_values),
                    "has_health_check": rs.health_check_url is not None,
                    "has_login_sequence": len(rs.login_sequence) > 0,
                }
            return roles_data

    @classmethod
    def from_dict(cls, data: dict[str, Any], **kwargs: Any) -> "AuthSessionManager":
        """Restore an ``AuthSessionManager`` from a previously serialized dict.

        Only token/CSRF state is restored; login sequences and health-check
        URLs must be re-registered via ``register_role()``.
        """
        manager = cls(**kwargs)
        with manager._lock:
            for role, state in data.items():
                rs = manager._roles.get(role)
                if rs is None:
                    rs = RoleSession(session=manager._build_session())
                    manager._roles[role] = rs
                rs.oauth_token = state.get("oauth_token")
                rs.refresh_token = state.get("refresh_token")
                rs.token_expiry = state.get("token_expiry", 0.0)
                rs.csrf_token = state.get("csrf_token")
                rs.created_at = state.get("created_at", time.time())
                rs.extracted_values = dict(state.get("extracted_values", {}))

        return manager
