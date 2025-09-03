from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import List

from dotenv import load_dotenv


@dataclass
class Settings:
    groq_api_keys: List[str]
    groq_model: str


def get_settings() -> Settings:
    load_dotenv(override=False)
    keys_raw = os.getenv("GROQ_API_KEYS", "").strip()
    keys: List[str] = [k.strip() for k in keys_raw.split(",") if k.strip()]
    # Shuffle order to distribute load if multiple keys are provided
    random.shuffle(keys)
    model = os.getenv("GROQ_MODEL", "llama3-8b-8192")
    return Settings(groq_api_keys=keys, groq_model=model)

