"""MOZA device-profile registry.

``load_profiles()`` returns ``{key: DeviceProfile}`` for every device the
simulator can present. It replaces the literal ``WHEEL_MODELS`` dict in
wheel_sim.py, which now derives its dict view via ``to_legacy_dict()``.

Profiles live in category sub-packages (wheels/, dashes/, pedals/,
standalone/). Each module exports a module-level ``PROFILE`` (a DeviceProfile).
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Dict

from .schema import DeviceProfile  # re-export for convenience

# Category sub-packages scanned for `PROFILE`-exporting modules.
_CATEGORIES = ("wheels", "dashes", "pedals", "standalone")


def load_profiles() -> Dict[str, DeviceProfile]:
    """Discover and load every device profile, keyed by ``DeviceProfile.key``."""
    out: Dict[str, DeviceProfile] = {}
    for cat in _CATEGORIES:
        try:
            pkg = importlib.import_module(f"{__name__}.{cat}")
        except ModuleNotFoundError:
            continue
        for mod_info in pkgutil.iter_modules(pkg.__path__):
            name = mod_info.name
            if name.startswith("_"):
                continue
            mod = importlib.import_module(f"{__name__}.{cat}.{name}")
            prof = getattr(mod, "PROFILE", None)
            if isinstance(prof, DeviceProfile):
                if prof.key in out:
                    raise ValueError(
                        f"duplicate profile key '{prof.key}' "
                        f"({cat}.{name})")
                out[prof.key] = prof
    return out
