from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_CACHE = Path("data/cache/cti_cache.json")


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_cache(path: Path = DEFAULT_CACHE) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cache(cache: Dict[str, Any], path: Path = DEFAULT_CACHE) -> None:
    _ensure_parent(path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def get_cached(cache: Dict[str, Any], key: str) -> Optional[Dict[str, Any]]:
    val = cache.get(key)
    if isinstance(val, dict):
        return val
    return None


def set_cached(cache: Dict[str, Any], key: str, value: Dict[str, Any]) -> None:
    cache[key] = value

