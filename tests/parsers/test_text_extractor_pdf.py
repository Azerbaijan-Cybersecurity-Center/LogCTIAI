from pathlib import Path

from PyPDF2 import PdfWriter

from src.parsers.text_extractor import extract_text_from_pdf


def test_extract_text_from_pdf_blank(tmp_path: Path):
    pdf_path = tmp_path / "blank.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with pdf_path.open("wb") as f:
        writer.write(f)

    text = extract_text_from_pdf(pdf_path)
    # Blank page yields empty string but exercises the code path
    assert isinstance(text, str)
    assert text == ""

