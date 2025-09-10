from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
from typing import List, Optional, Set

from dotenv import load_dotenv
from rich import print
from rich.progress import Progress

from src.core.scanner import ScanOptions, scan_ips_enrich
from src.report.pdf_report import PDFReport
import csv
import json


def _read_ips_from_file(path: Path) -> List[str]:
    ips: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                ipaddress.ip_address(s)
                ips.append(s)
            except ValueError:
                continue
    return ips


def _load_offline_blocklist() -> Set[str]:
    path = os.getenv("OFFLINE_IP_BLOCKLIST")
    bad: Set[str] = set()
    if path and Path(path).exists():
        bad.update(_read_ips_from_file(Path(path)))
    return bad


def cmd_scan_ips(args: argparse.Namespace) -> int:
    load_dotenv()
    out: Path = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    input_path = Path(args.input_path)
    if not input_path.exists():
        print(f"[red]Input file not found:[/red] {input_path}")
        return 2

    ips = _read_ips_from_file(input_path)
    print(f"[bold]Loaded[/bold] {len(ips)} IPs, {len(list(dict.fromkeys(ips)))} unique.")

    opts = ScanOptions(
        cti_max=args.cti_max,
        use_cache=not args.no_cache,
        no_cti=args.no_cti,
        offline_blocklist=_load_offline_blocklist(),
        cti_rate_per_sec=args.cti_rate,
        cti_burst=args.cti_burst,
        save_every=args.save_every,
        abuseipdb=(not getattr(args, "no_abuseipdb", False)),
        abuseipdb_threshold=getattr(args, "abuse_threshold", 50),
        abuseipdb_rate_per_sec=getattr(args, "abuse_rate", 0.8),
        abuseipdb_burst=getattr(args, "abuse_burst", 1),
        workers=getattr(args, "workers", 4),
    )

    with Progress() as progress:
        task = progress.add_task("Scanning", total=len(ips))
        rows, summary, errors = scan_ips_enrich(
            ips,
            opts,
            on_progress=lambda i, t: progress.update(task, completed=i, total=t),
        )

    if not args.include_suspicious:
        rows = [r for r in rows if r["classification"] == "malicious"]

    pdf = PDFReport()
    blob = pdf.build(malicious_rows=rows, summary=summary)

    out_pdf = out / "ip_threat_report.pdf"
    with out_pdf.open("wb") as f:
        f.write(blob)
    print(f"[green]Report written:[/green] {out_pdf}")
    # Write CSV/JSON for machine use
    out_json = out / "ip_threat_report.json"
    with out_json.open("w", encoding="utf-8") as f:
        json.dump({
            "summary": summary,
            "rows": rows,
        }, f, ensure_ascii=False, indent=2)
    out_csv = out / "ip_threat_report.csv"
    if rows:
        with out_csv.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    print(f"[green]Also wrote:[/green] {out_json}, {out_csv}")
    if errors:
        print(f"[yellow]{len(errors)} errors occurred. See log above or rerun with fewer IPs.[/yellow]")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="logctiai",
        description="Scan IPs with CTI and generate PDF report.",
    )
    sub = parser.add_subparsers(dest="command")

    sp = sub.add_parser("scan-ips", help="Scan IPs from a file and output a PDF report")
    sp.add_argument("input_path", type=str, help="Path to text file with one IP per line")
    sp.add_argument("--out", type=str, default="data/processed", help="Output directory")
    sp.add_argument(
        "--cti-max",
        type=int,
        default=200,
        help="Max CTI lookups (deduped). Use -1 for all IPs",
    )
    sp.add_argument("--no-cache", action="store_true", help="Do not use or update the cache")
    sp.add_argument("--include-suspicious", action="store_true", help="Include suspicious in report")
    sp.add_argument("--no-cti", action="store_true", help="Disable CTI calls (offline)")
    sp.add_argument("--cti-rate", type=float, default=1.0, help="CTI requests per second")
    sp.add_argument("--cti-burst", type=int, default=1, help="CTI burst size")
    sp.add_argument("--save-every", type=int, default=50, help="Save cache every N updates")
    sp.add_argument("--no-abuseipdb", action="store_true", help="Disable AbuseIPDB lookups (if not desired)")
    sp.add_argument("--abuse-threshold", type=int, default=50, help="AbuseIPDB confidence threshold for malicious")
    sp.add_argument("--abuse-rate", type=float, default=0.8, help="AbuseIPDB requests per second")
    sp.add_argument("--abuse-burst", type=int, default=1, help="AbuseIPDB burst size")
    sp.add_argument("--workers", type=int, default=4, help="Parallel workers for CTI (limit-safe)")
    sp.set_defaults(func=cmd_scan_ips)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
