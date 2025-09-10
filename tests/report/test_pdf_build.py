from src.report.pdf_report import PDFReport


def test_pdf_build_nonempty():
    pdf = PDFReport()
    rows = [
        {
            "ip": "8.8.8.8",
            "classification": "malicious",
            "country": "US",
            "malicious": "5",
            "suspicious": "0",
            "harmless": "0",
            "as_owner": "GOOGLE",
        }
    ]
    blob = pdf.build(rows, {"total": 1, "malicious": 1, "suspicious": 0, "harmless": 0})
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 1000

