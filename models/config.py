from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanConfig:
    target: str = ""
    output: str = "reports"
    format: str = "html"
    threads: int = 10
    timeout: int = 10
    rps: float = 5.0
    verbose: bool = False
    passive: bool = False
    dry_run: bool = False
    resume: bool = False
    stealth: bool = False
    no_rich: bool = False
    no_mask_curl: bool = False
    use_new_scanners: bool = False

    cookies: str = ""
    cookies_alt: str = ""
    headers: list[str] = field(default_factory=list)
    auth: str = ""
    proxy: str = ""
    no_verify_ssl: bool = False

    oob_host: str = ""
    headless: bool = False
    wordlist: str = ""
    scope: str = ""
    exclude_patterns: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)
    crawl_depth: int = 2
    max_urls: int = 200
    delay: float = 0.0
    retries: int = 3
    autosave_interval: int = 0
    max_js_files: int = 50
    modules: list[str] | None = None
    disable_modules: list[str] | None = None
    module_params: dict[str, Any] = field(default_factory=dict)
    verify_only: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanConfig":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        kwargs = {k: v for k, v in d.items() if k in known}
        kwargs.setdefault("module_params", d.get("module_params", {}))
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in self.__dataclass_fields__.values()}
