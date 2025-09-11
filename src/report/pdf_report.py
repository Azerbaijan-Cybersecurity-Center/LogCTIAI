from __future__ import annotations

from datetime import datetime, timezone
import base64
from pathlib import Path
from typing import Iterable, List, Mapping, Dict

from fpdf import FPDF


class PDFReport:
    def __init__(self, title: str = "IP Threat Report") -> None:
        self.title = title
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)

    def _header(self) -> None:
        self.pdf.set_font("Helvetica", "B", 16)
        self.pdf.cell(0, 10, self.title, ln=True)
        self.pdf.set_font("Helvetica", "", 10)
        self.pdf.cell(0, 6, f"Generated: {datetime.now(timezone.utc).isoformat()}", ln=True)

    def _summary(self, total: int, malicious: int, suspicious: int) -> None:
        self.pdf.ln(4)
        self.pdf.set_font("Helvetica", "B", 12)
        self.pdf.cell(0, 8, "Summary", ln=True)
        self.pdf.set_font("Helvetica", size=11)
        self.pdf.cell(0, 6, f"Total IPs scanned: {total}", ln=True)
        self.pdf.cell(0, 6, f"Malicious: {malicious} | Suspicious: {suspicious}", ln=True)

    def _bar_chart(self, total: int, malicious: int, suspicious: int, harmless: int) -> None:
        if total <= 0:
            return
        self.pdf.ln(2)
        self.pdf.set_font("Helvetica", "B", 11)
        self.pdf.cell(0, 7, "Overview", ln=True)
        x = self.pdf.get_x()
        y = self.pdf.get_y()
        width = 180
        height = 8
        # Compute proportional widths
        w_mal = width * (malicious / total)
        w_sus = width * (suspicious / total)
        w_har = max(0.0, width - w_mal - w_sus)
        # Malicious - red
        self.pdf.set_fill_color(220, 53, 69)
        self.pdf.rect(x, y, w_mal, height, style="F")
        # Suspicious - orange
        self.pdf.set_fill_color(255, 159, 67)
        self.pdf.rect(x + w_mal, y, w_sus, height, style="F")
        # Harmless - green
        self.pdf.set_fill_color(40, 167, 69)
        self.pdf.rect(x + w_mal + w_sus, y, w_har, height, style="F")
        self.pdf.ln(height + 2)
        self.pdf.set_font("Helvetica", size=10)
        self.pdf.cell(0, 6, "Legend: red=malicious, orange=suspicious, green=harmless", ln=True)

    def _table_header(self, headers: List[str]) -> None:
        self.pdf.set_font("Helvetica", "B", 11)
        col_widths = [40, 28, 28, 18, 18, 18, 45]  # tuned for A4
        for w, h in zip(col_widths, headers):
            self.pdf.cell(w, 8, h, border=1)
        self.pdf.ln(8)

    def _sanitize(self, s: str) -> str:
        try:
            return s.encode("latin-1", errors="replace").decode("latin-1")
        except Exception:
            return s

    def _table_rows(self, rows: Iterable[Mapping[str, str]]) -> None:
        self.pdf.set_font("Helvetica", size=10)
        col_widths = [40, 28, 28, 18, 18, 18, 45]
        for row in rows:
            cells = [
                row.get("ip", ""),
                row.get("classification", ""),
                row.get("country", ""),
                str(row.get("malicious", "")),
                str(row.get("suspicious", "")),
                str(row.get("harmless", "")),
                (row.get("as_owner", "") or "")[:45],
            ]
            # Row color based on classification
            cls = (row.get("classification") or "").lower()
            if cls == "malicious":
                self.pdf.set_fill_color(255, 235, 238)  # light red
            elif cls == "suspicious":
                self.pdf.set_fill_color(255, 248, 225)  # light orange
            else:
                self.pdf.set_fill_color(245, 255, 245)  # very light green
            # Draw cells; try to render a flag image in the Country column
            for idx, (w, c) in enumerate(zip(col_widths, cells)):
                if idx == 2:  # country column
                    x = self.pdf.get_x()
                    y = self.pdf.get_y()
                    cc = str(c or "").upper()
                    flag = Path("data/assets/flags") / f"{cc}.png"
                    if cc and flag.exists():
                        try:
                            self.pdf.image(str(flag), x=x + 1, y=y + 1, w=5, h=5)
                            text = f" {cc}"
                        except Exception:
                            text = cc
                    elif cc:
                        # Create a tiny placeholder flag on-the-fly so PDFs always render
                        try:
                            self._ensure_flag_placeholder(flag)
                            if flag.exists():
                                try:
                                    self.pdf.image(str(flag), x=x + 1, y=y + 1, w=5, h=5)
                                    text = f" {cc}"
                                except Exception:
                                    text = cc
                            else:
                                text = cc
                        except Exception:
                            text = cc
                    else:
                        text = cc
                    self.pdf.cell(w, 7, self._sanitize(text), border=1, fill=True)
                else:
                    self.pdf.cell(w, 7, self._sanitize(str(c)), border=1, fill=True)
            self.pdf.ln(7)

    def _ensure_flag_placeholder(self, path: Path) -> None:
        """Ensure a minimal placeholder PNG exists at the given path.

        We write a 1x1 transparent PNG so the layout remains consistent.
        """
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                return
            # 1x1 transparent PNG
            b64 = (
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Yb4UvoAAAAASUVORK5CYII="
            )
            data = base64.b64decode(b64)
            with path.open("wb") as f:
                f.write(data)
        except Exception:
            # best-effort; ignore failures
            pass

    def build(self, malicious_rows: List[Mapping[str, str]], summary: Mapping[str, int], ai_summary: str | None = None) -> bytes:
        self.pdf.add_page()
        self._header()
        # Optional AI executive summary
        if ai_summary:
            self.pdf.ln(3)
            self.pdf.set_font("Helvetica", "B", 12)
            self.pdf.cell(0, 8, "AI Executive Summary", ln=True)
            self.pdf.set_font("Helvetica", size=11)
            # Render in wrapped cells
            for paragraph in ai_summary.strip().split("\n"):
                if paragraph.strip():
                    self.pdf.multi_cell(0, 6, self._sanitize(paragraph.strip()))
            self.pdf.ln(2)
        self._summary(
            total=summary.get("total", 0),
            malicious=summary.get("malicious", 0),
            suspicious=summary.get("suspicious", 0),
        )
        self._bar_chart(
            total=summary.get("total", 0),
            malicious=summary.get("malicious", 0),
            suspicious=summary.get("suspicious", 0),
            harmless=summary.get("harmless", 0),
        )
        self.pdf.ln(4)
        self.pdf.set_font("Helvetica", "B", 12)
        self.pdf.cell(0, 8, "Malicious IPs", ln=True)
        headers = ["IP", "Class", "Country", "Mal", "Susp", "Harmless", "AS Owner"]
        self._table_header(headers)
        self._table_rows(malicious_rows)
        # Second page: Top countries
        counts: Dict[str, int] = {}
        for r in malicious_rows:
            c = (r.get("country") or "").upper()
            if not c:
                continue
            counts[c] = counts.get(c, 0) + 1
        if counts:
            self.pdf.add_page()
            self.pdf.set_font("Helvetica", "B", 12)
            self.pdf.cell(0, 8, "Top Countries (by malicious count)", ln=True)
            self.pdf.set_font("Helvetica", size=11)
            for country, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:15]:
                self.pdf.cell(0, 6, f"{country}: {cnt}", ln=True)
        data = self.pdf.output(dest="S")
        try:
            return bytes(data)
        except Exception:
            # Fallback: older FPDF may return str
            return str(data).encode("latin-1", errors="replace")
