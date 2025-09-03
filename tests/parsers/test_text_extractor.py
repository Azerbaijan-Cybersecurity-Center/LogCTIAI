from pathlib import Path

from src.parsers.text_extractor import read_text_file, chunk_text


def test_read_text_and_chunk(tmp_path: Path):
    p = tmp_path / "sample.txt"
    p.write_text("abcdef", encoding="utf-8")
    txt = read_text_file(p)
    assert txt == "abcdef"
    parts = list(chunk_text(txt, max_chars=2))
    assert parts == ["ab", "cd", "ef"]

