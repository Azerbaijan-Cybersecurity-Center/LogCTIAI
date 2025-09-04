from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import List, Dict

from rich.console import Console
from rich.progress import track
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.json import JSON as RichJSON
from rich.traceback import install as rich_traceback_install

from .parsers.text_extractor import extract_text_from_pdf, read_text_file
from .parsers.log_parser import parse_lines, parse_line
from .enrichers.llm_enricher import enrich_log_records
from .enrichers.cti_service import cti_for_ips
from .parsers.ua_analysis import detect_suspicious_user_agent
from .reports.report_builder import (
    build_text_report,
    build_markdown_report,
    build_malicious_ai_report,
)
from .config import get_settings
from .groq_client import GroqRotatingClient


rich_traceback_install(show_locals=False)
console = Console()


def process_log(
    path: Path,
    out_dir: Path,
    use_llm: bool,
    limit: int | None = None,
    out_format: str = "jsonl",
    with_cti: bool = True,
    build_reports: bool = True,
    *,
    llm_sample: int | None = None,
    llm_group_by: list[str] | None = None,
    group_window_sec: int | None = None,
    llm_gate_min_4xx: int | None = None,
    llm_gate_ua: bool = False,
    cti_scope: str = "suspicious",
    cti_max: int | None = None,
    cti_batch_size: int | None = None,
    cti_batch_pause: float = 0.0,
    ai_malicious_report: bool = False,
) -> Path:
    console.rule("[bold cyan]🔎 Parsing Log")
    console.log(f"Parsing log: [bold]{path}")
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    if limit is not None:
        lines = lines[:limit]
    records = [r.to_dict() for r in parse_lines(lines)]
    console.log(f"Parsed [bold green]{len(records)}[/] records")
    enriched = enrich_log_records(
        records,
        use_llm=use_llm,
        llm_sample=llm_sample,
        group_by=llm_group_by,
        group_window_sec=group_window_sec,
        llm_gate_min_4xx=llm_gate_min_4xx,
        llm_gate_ua=llm_gate_ua,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    if out_format == "csv":
        out_path = out_dir / f"{path.stem}.csv"
        fieldnames = list({k for r in enriched for k in r.keys()})
        with out_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            for r in enriched:
                writer.writerow(r)
    else:
        out_path = out_dir / f"{path.stem}.jsonl"
        with out_path.open("w", encoding="utf-8") as f:
            for r in enriched:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    # If requested, compute CTI + stats and build reports
    if build_reports:
        console.rule("[bold blue]🧠 Stats + CTI + Reports")
        overall_stats, suspicious_rows, ai_insight = summarize_and_cti(
            enriched_records=enriched,
            use_llm=use_llm,
            with_cti=with_cti,
            cti_scope=cti_scope,
            cti_max=cti_max,
            cti_batch_size=cti_batch_size,
            cti_batch_pause=cti_batch_pause,
        )
        reports_dir = out_dir / "reports"
        txt_path = build_text_report(
            out_dir=reports_dir,
            suspicious=suspicious_rows,
            overall_stats=overall_stats,
            ai_insight=ai_insight,
        )
        md_path = build_markdown_report(
            out_dir=reports_dir,
            suspicious=suspicious_rows,
            overall_stats=overall_stats,
            ai_insight=ai_insight,
        )
        console.log(f"Reports saved: [bold]{txt_path}[/], [bold]{md_path}[/]")

        # Optional: generate a detailed malicious activity report using LLM
        if ai_malicious_report and use_llm and suspicious_rows:
            try:

                # Select IPs with strongest malicious indicators
                def is_malicious(row: dict[str, object]) -> bool:
                    risk = str(row.get("risk", "unknown")).lower()
                    talos = str(row.get("talos_reputation", "")).lower()
                    vt_mal = int(row.get("vt_malicious") or 0)
                    vt_susp = int(row.get("vt_suspicious") or 0)
                    return (
                        risk in {"high"}
                        or talos in {"untrusted", "malicious"}
                        or vt_mal >= 1
                        or vt_susp >= 3
                    )

                malicious = [r for r in suspicious_rows if is_malicious(r)]
                if malicious:
                    # Derive minimal per-IP context from enriched events (top paths/UA)
                    from collections import Counter as _C
                    per_ip_paths: dict[str, list[tuple[str, int]]] = {}
                    per_ip_ua: dict[str, str] = {}
                    for ip in {str(r.get("ip")) for r in malicious}:
                        paths = _C([str(e.get("path")) for e in enriched if str(e.get("ip")) == ip and e.get("path")])
                        per_ip_paths[ip] = paths.most_common(5)
                        # pick any UA string observed
                        for e in enriched:
                            if str(e.get("ip")) == ip and (e.get("ua") or e.get("user_agent")):
                                per_ip_ua[ip] = str(e.get("ua") or e.get("user_agent"))
                                break
                    # Build prompt
                    insight_req = {
                        "malicious": malicious[:20],  # cap to keep prompt small
                        "per_ip_top_paths": per_ip_paths,
                        "per_ip_ua": per_ip_ua,
                    }
                    client = GroqRotatingClient()
                    content = client.chat([
                        {
                            "role": "system",
                            "content": (
                                "You are a senior SOC analyst. Draft a concise but detailed incident note summarizing malicious "
                                "activity detected in logs corroborated by CTI (AbuseIPDB, Talos, VirusTotal). "
                                "Include: IP(s), CTI signals, notable paths, suspected TTPs, and recommended actions (blocking, WAF rules, triage). "
                                "Use clear sections and bullets."
                            ),
                        },
                        {"role": "user", "content": json.dumps(insight_req)},
                    ])
                    rpt_txt, rpt_md = build_malicious_ai_report(reports_dir, content)
                    console.log(f"Malicious AI report saved: [bold]{rpt_txt}[/], [bold]{rpt_md}[/]")
                else:
                    console.log("[dim]No strong malicious CTI signals; skipping detailed AI report.")
            except Exception as e:  # pragma: no cover - network/env specific
                console.log(f"[dim]Malicious AI report unavailable: {e}")

    return out_path


def summarize_and_cti(
    enriched_records: list[dict[str, object]],
    use_llm: bool,
    with_cti: bool = True,
    *,
    cti_scope: str = "suspicious",  # 'suspicious' | 'all'
    cti_max: int | None = None,
    cti_batch_size: int | None = None,
    cti_batch_pause: float = 0.0,
) -> tuple[dict[str, object], list[dict[str, object]], str | None]:
    """Compute overall stats, annotate suspicious IPs with CTI + UA, and optional AI note.

    Returns: (overall_stats, suspicious_rows, ai_insight)
    """
    # Overall stats
    total_requests = len(enriched_records)
    unique_ips = len({r.get("ip") for r in enriched_records if r.get("ip")})
    status_counts = Counter(str(r.get("status")) for r in enriched_records)
    r200 = status_counts.get("200", 0)
    r404 = status_counts.get("404", 0)
    ratio_404_200 = round((r404 / r200), 3) if r200 else None
    overall_stats = {
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "ratio_404_200": ratio_404_200,
    }

    # Per-IP stats
    settings = get_settings()
    per_ip = defaultdict(lambda: {"requests": 0, "errors_4xx": 0, "ua_suspicious": False})
    for r in enriched_records:
        ip = str(r.get("ip") or "")
        if not ip:
            continue
        per_ip[ip]["requests"] += 1
        try:
            status = int(r.get("status", 0))
        except Exception:
            status = 0
        if 400 <= status < 500:
            per_ip[ip]["errors_4xx"] += 1
        ua_susp, _ = detect_suspicious_user_agent(
            str(r.get("ua") or r.get("user_agent") or ""),
            patterns=settings.suspicious_ua_patterns or None,
        )
        per_ip[ip]["ua_suspicious"] = per_ip[ip]["ua_suspicious"] or ua_susp

    # CTI lookup
    cti_map: dict[str, dict[str, object]] = {}
    if with_cti:
        try:
            # Decide candidate IPs to look up: prefer suspicious or top 4xx
            if cti_scope == "all":
                candidates = list(per_ip.keys())
            else:
                candidates = [
                    ip
                    for ip, stats in per_ip.items()
                    if (stats["errors_4xx"] >= settings.risk_4xx_threshold) or stats["ua_suspicious"]
                ]
                # Sort by 4xx desc then requests desc
                candidates.sort(key=lambda i: (per_ip[i]["errors_4xx"], per_ip[i]["requests"]), reverse=True)
            if cti_max is not None and cti_max >= 0:
                candidates = candidates[:cti_max]
            cti_results = cti_for_ips(
                candidates,
                virustotal_api_key=settings.virustotal_api_key,
                batch_size=cti_batch_size,
                pause_seconds=cti_batch_pause,
            )
            cti_map = {ip: v.to_dict() for ip, v in cti_results.items()}
        except Exception as e:  # pragma: no cover - network / env specific
            console.log(f"[dim]CTI lookup failed: {e}. Continuing without CTI.")
            cti_map = {}

    # Build suspicious rows
    suspicious_rows: list[dict[str, object]] = []
    # Load offline blocklist if provided
    offline_blocked: set[str] = set()
    if settings.offline_ip_blocklist:
        try:
            from pathlib import Path as _P
            p = _P(settings.offline_ip_blocklist)
            if p.exists():
                offline_blocked = {line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.strip().startswith('#')}
        except Exception:
            offline_blocked = set()
    for ip, stats in per_ip.items():
        cti = cti_map.get(ip, {})
        risk = str(cti.get("risk", "unknown"))
        # Offline blocklist escalation
        if ip in offline_blocked and risk != "high":
            risk = "high"
        is_susp = (
            risk in {"high", "medium"}
            or stats["errors_4xx"] >= settings.risk_4xx_threshold
            or stats["ua_suspicious"]
        )
        if not is_susp:
            continue
        row = {
            "ip": ip,
            "risk": risk,
            "abuse_confidence_score": cti.get("abuse_confidence_score"),
            "total_reports": cti.get("total_reports"),
            "country": cti.get("country"),
            "url": cti.get("url"),
            "talos_reputation": cti.get("talos_reputation"),
            "talos_owner": cti.get("talos_owner"),
            "vt_malicious": cti.get("vt_malicious"),
            "vt_suspicious": cti.get("vt_suspicious"),
            **stats,
        }
        # One-line AI note from existing enrichment (if any)
        # Try to pick any record from that IP that has severity/rationale
        note = None
        for r in enriched_records:
            if r.get("ip") == ip and r.get("rationale"):
                note = str(r.get("rationale"))
                break
        row["ai_one_liner"] = note
        suspicious_rows.append(row)

    # Optional anomaly insight via LLM
    ai_insight: str | None = None
    if use_llm:
        try:
            client = GroqRotatingClient()
            insight_req = {
                "total_requests": total_requests,
                "unique_ips": unique_ips,
                "status_counts": dict(status_counts),
                "ratio_404_200": ratio_404_200,
                "top_suspicious": [{k: v for k, v in row.items() if k in {"ip", "risk", "requests", "errors_4xx"}} for row in suspicious_rows[:5]],
            }
            ai_insight = client.chat([
                {"role": "system", "content": "You are a SOC analyst. Identify notable anomalies succinctly."},
                {"role": "user", "content": json.dumps(insight_req)},
            ])
        except Exception as e:  # pragma: no cover - network specific
            console.log(f"[dim]AI insight unavailable: {e}")
            ai_insight = None

    return overall_stats, suspicious_rows, ai_insight


def process_pdf(path: Path, out_dir: Path, use_llm: bool) -> Path:
    console.rule("[bold magenta]📄 PDF Extraction")
    console.log(f"Extracting text from PDF: [bold]{path}")
    text = extract_text_from_pdf(path)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{path.stem}.txt"
    out_path.write_text(text, encoding="utf-8")
    # Optional: one-shot summary with LLM
    if use_llm and text.strip():
        client = GroqRotatingClient()
        summary = client.chat([
            {"role": "system", "content": "Summarize the key findings in 5 bullets."},
            {"role": "user", "content": text[:8000]},
        ])
        (out_dir / f"{path.stem}.summary.txt").write_text(summary, encoding="utf-8")
    return out_path


def process_txt(path: Path, out_dir: Path, use_llm: bool) -> Path:
    console.rule("[bold yellow]📄 TXT Copy")
    console.log(f"Copying TXT: [bold]{path}")
    text = read_text_file(path)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{path.name}"
    out_path.write_text(text, encoding="utf-8")
    return out_path


def _print_summary(records: List[Dict[str, object]]) -> None:
    if not records:
        console.print(Panel("No records to summarize.", title="Summary", style="dim"))
        return
    statuses = Counter(r.get("status", "?") for r in records)
    ips = Counter(r.get("ip", "?") for r in records if r.get("ip"))
    methods = Counter(r.get("method", "?") for r in records if r.get("method"))

    table = Table(title="HTTP Status Distribution", show_edge=True, header_style="bold cyan")
    table.add_column("Status", style="bold")
    table.add_column("Count", justify="right")
    for status, count in sorted(statuses.items()):
        color = "green" if str(status).startswith("2") else "yellow" if str(status).startswith("3") else "red"
        table.add_row(f"[{color}]{status}[/]", f"{count}")

    top_table = Table(title="Top IPs / Methods", header_style="bold magenta")
    top_table.add_column("Top IPs", style="bold")
    top_table.add_column("Count", justify="right")
    top_table.add_column("Methods", style="bold")
    top_table.add_column("Count", justify="right")
    for i in range(max(len(ips), len(methods), 5)):
        ip, ip_c = ("", "")
        meth, meth_c = ("", "")
        if i < len(ips):
            ip, ip_c = list(ips.items())[i]
        if i < len(methods):
            meth, meth_c = list(methods.items())[i]
        if ip or meth:
            top_table.add_row(str(ip), str(ip_c), str(meth), str(meth_c))

    console.print(Panel.fit(table, title="Summary", border_style="cyan"))
    console.print(Panel.fit(top_table, border_style="magenta"))


def _preview_records(records: List[Dict[str, object]], n: int) -> None:
    console.rule("[bold green]🔬 Preview")
    for r in records[:n]:
        sev = str(r.get("severity", "unknown")).lower()
        sev_color = {
            "high": "bold red",
            "medium": "yellow",
            "low": "green",
        }.get(sev, "cyan")
        console.print(Panel(
            RichJSON.from_data(r, indent=2),
            title=f"Severity: [{sev_color}]{sev}[/]",
            border_style=sev_color,
        ))


def main(argv: List[str] | None = None) -> int:
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Colorful Log + CTI pipeline with Groq enrichment")
    parser.add_argument("input", type=str, help="Path to input file (log, pdf, txt)")
    parser.add_argument("--out", type=str, default="data/processed", help="Output directory")
    parser.add_argument("--no-llm", action="store_true", help="Disable LLM enrichment")
    parser.add_argument("--limit", type=int, default=None, help="Limit records for quick tests")
    parser.add_argument("--summary", action="store_true", help="Print colorful summary in terminal")
    parser.add_argument("--preview", type=int, default=0, help="Preview first N enriched records")
    parser.add_argument("--format", choices=["jsonl", "csv"], default="jsonl", help="Output format for logs")
    parser.add_argument("--no-cti", action="store_true", help="Disable CTI lookups")
    parser.add_argument("--no-reports", action="store_true", help="Do not build text/markdown reports")
    parser.add_argument("--ai-malicious-report", action="store_true", help="Generate detailed AI report for malicious CTI signals")
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="Terminal color policy")
    # LLM request controls
    parser.add_argument("--llm-sample", type=int, default=200, help="Limit LLM calls by sampling this many groups (0=all)")
    parser.add_argument(
        "--llm-group-by",
        choices=["none", "ip", "signature"],
        default="ip",
        help="Group records before enrichment to reduce LLM calls: 'ip' (minimal), 'signature' (ip+path+status+ua), or 'none'",
    )
    parser.add_argument("--group-window", type=int, default=0, help="Optional time window (seconds) to include in grouping key")
    parser.add_argument("--llm-gate-4xx", type=int, default=0, help="Only send groups with at least this many 4xx to the LLM (0=disabled)")
    parser.add_argument("--llm-gate-ua", action="store_true", help="Only send groups with suspicious UA patterns to the LLM")
    # CTI request controls
    parser.add_argument("--cti-scope", choices=["suspicious", "all"], default="suspicious", help="Which IPs to look up for CTI")
    parser.add_argument("--cti-max", type=int, default=100, help="Max CTI lookups (0=unlimited)")
    args = parser.parse_args(argv)

    # Configure console color policy
    global console
    force_term = args.color == "always"
    no_color = args.color == "never"
    console = Console(force_terminal=force_term, no_color=no_color)

    console.print(Rule(title="[bold cyan]🧭 Log + CTI Pipeline"))

    use_llm = not args.no_llm and bool(settings.groq_api_keys)
    if not use_llm:
        console.log("[dim]LLM enrichment disabled (no keys or --no-llm)")

    path = Path(args.input)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    suffix = path.suffix.lower()
    out_path: Path
    enriched_records: List[Dict[str, object]] | None = None

    # Heuristic: treat .log as logs; for .txt, auto-detect by trying to parse a few lines
    def _looks_like_log_file(p: Path, sample_lines: int = 200) -> bool:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False
        lines = text.splitlines()[:sample_lines]
        parsed = 0
        for ln in lines:
            if parse_line(ln):
                parsed += 1
                # One hit is enough to call it a log
                break
        return parsed > 0

    if suffix == ".log" or (suffix == ".txt" and _looks_like_log_file(path)):
        # Compute grouping config for LLM
        gb = None
        if args.llm_group_by == "ip":
            gb = ["ip"]
        elif args.llm_group_by == "signature":
            gb = ["ip", "path", "status", "ua"]
        # Normalize sample value
        sample = None if args.llm_sample in (None, 0) else max(0, int(args.llm_sample))
        group_window = None if args.group_window in (None, 0) else max(1, int(args.group_window))
        gate4xx = None if args.llm_gate_4xx in (None, 0) else max(1, int(args.llm_gate_4xx))
        out_path = process_log(
            path,
            out_dir,
            use_llm=use_llm,
            limit=args.limit,
            out_format=args.format,
            with_cti=not args.no_cti,
            build_reports=not args.no_reports,
            llm_sample=sample,
            llm_group_by=gb,
            group_window_sec=group_window,
            llm_gate_min_4xx=gate4xx,
            llm_gate_ua=bool(args.llm_gate_ua),
            cti_scope=args.cti_scope,
            cti_max=(None if args.cti_max in (None, 0) else max(0, int(args.cti_max))),
            cti_batch_size=(None if getattr(args, 'cti_batch_size', 0) in (None, 0) else max(1, int(args.cti_batch_size))),
            cti_batch_pause=float(getattr(args, 'cti_batch_pause', 0.0) or 0.0),
            ai_malicious_report=bool(args.ai_malicious_report),
        )
        # Load enriched to drive summary/preview
        enriched_records = [json.loads(l) for l in (out_dir / f"{path.stem}.jsonl").read_text(encoding="utf-8").splitlines()] if args.format == "jsonl" else None
    elif suffix == ".pdf":
        out_path = process_pdf(path, out_dir, use_llm=use_llm)
    elif suffix == ".txt":
        out_path = process_txt(path, out_dir, use_llm=use_llm)
    else:
        console.print(f"[bold red]Unsupported file type:[/] {suffix}")
        return 2

    # Optional summary and preview for logs
    if enriched_records is not None:
        if args.summary:
            _print_summary(enriched_records)
        if args.preview > 0:
            _preview_records(enriched_records, args.preview)

    console.print(f"✅ [bold]Done:[/] {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
