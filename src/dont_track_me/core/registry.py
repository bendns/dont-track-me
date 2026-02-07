"""Module registry — auto-discovers and registers all tracking-vector modules."""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

from dont_track_me import modules as modules_pkg

if TYPE_CHECKING:
    from dont_track_me.core.base import BaseModule


_registry: dict[str, BaseModule] = {}
_discovered = False


def _discover_modules() -> None:
    """Walk dont_track_me.modules.* and instantiate every BaseModule subclass."""
    global _discovered
    if _discovered:
        return

    from dont_track_me.core.base import BaseModule

    for _importer, modname, ispkg in pkgutil.iter_modules(
        modules_pkg.__path__, modules_pkg.__name__ + "."
    ):
        if not ispkg:
            continue
        # Import the module.py inside each sub-package
        try:
            mod = importlib.import_module(f"{modname}.module")
        except ImportError:
            continue

        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
            ):
                instance = attr()
                _registry[instance.name] = instance

    _discovered = True


def get_module(name: str) -> BaseModule | None:
    """Get a module by name."""
    _discover_modules()
    return _registry.get(name)


def get_all_modules() -> dict[str, BaseModule]:
    """Return all discovered modules."""
    _discover_modules()
    return dict(_registry)


def get_available_modules() -> dict[str, BaseModule]:
    """Return only modules whose dependencies are installed."""
    _discover_modules()
    return {k: v for k, v in _registry.items() if v.is_available()}
