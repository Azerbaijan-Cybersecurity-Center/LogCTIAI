from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PyPDF2 import PdfReader


def extract_text_from_pdf(path: Path) -> str:
    reader = PdfReader(str(path))
    texts = []
    for page in reader.pages:
        try:
            texts.append(page.extract_text() or "")
        except Exception:
            # Some PDFs may have images only; ignore silently here
            continue
    return "\n".join(texts)


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def chunk_text(text: str, max_chars: int = 4000) -> Iterable[str]:
    for i in range(0, len(text), max_chars):
        yield text[i : i + max_chars]

