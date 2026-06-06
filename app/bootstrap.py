from typing import Any

from app.capabilities import CapabilityRegistry
from app.container import ApplicationContainer


def bootstrap(config: dict[str, Any]) -> tuple[CapabilityRegistry, ApplicationContainer]:
    """Application startup sequence.

    1. Detect system capabilities.
    2. Create the dependency injection container.
    3. Return both so the caller can print summaries and wire services.
    """
    capabilities = CapabilityRegistry(config)
    container = ApplicationContainer(config, capabilities)
    return capabilities, container


def auto_upgrade_config(
    config: dict[str, Any],
    capabilities: CapabilityRegistry,
) -> dict[str, Any]:
    """Upgrade *config* in place based on detected *capabilities*.

    Mutates the passed dict and also returns it for convenience.
    """
    if capabilities.browser_validation:
        config.setdefault("enable_browser_validation", True)
        config.setdefault("enable_screenshots", True)

    if capabilities.has("oob_validation"):
        config.setdefault("enable_oob_validation", True)

    if not capabilities.browser_validation:
        config.setdefault("xss_confidence_floor", "medium")
        config["enable_browser_validation"] = False

    return config


def print_startup_summary(
    capabilities: CapabilityRegistry,
    config: dict[str, Any] | None = None,
) -> None:
    """Print the capability detection summary to the terminal."""
    capabilities.print_summary()
