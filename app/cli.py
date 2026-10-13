"""
cli.py - Command-Line Interface for AI SOC Assistant

Provides a rich terminal experience for SOC analysts to analyse
log files directly from the command line.

Usage
-----
::

    python -m app.cli analyse path/to/logfile.log
    python -m app.cli analyse path/to/ssh.log --type ssh --no-ai
    python -m app.cli analyse path/to/*.log --multiple
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Bootstrap path so module imports work from project root
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.analyzer import analyse_log_file, analyse_multiple_files, save_report
from app.core.ollama_client import OllamaClient, DEFAULT_MODEL

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_MAGENTA = "\033[95m"
_DIM = "\033[2m"


def _c(text: str, *codes: str) -> str:
    """Wrap text with ANSI codes."""
    return "".join(codes) + str(text) + _RESET


def _severity_colour(severity: str) -> str:
    colours = {
        "CRITICAL": _RED + _BOLD,
        "HIGH": _RED,
        "MEDIUM": _YELLOW,
        "LOW": _GREEN,
    }
    return _c(severity, colours.get(severity, _RESET))


def _confidence_colour(confidence: str) -> str:
    colours = {"high": _RED, "medium": _YELLOW, "low": _GREEN}
    return _c(confidence.upper(), colours.get(confidence.lower(), _RESET))


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = f"""
{_BOLD}{_CYAN}
╔══════════════════════════════════════════════════════════╗
║          AI-Powered SOC Assistant v1.0                   ║
║          Offline Threat Detection & Analysis             ║
╚══════════════════════════════════════════════════════════╝
{_RESET}"""


def print_banner() -> None:
    print(BANNER)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_separator(char: str = "─", width: int = 64) -> None:
    print(_c(char * width, _DIM))


def print_section(title: str) -> None:
    print()
    print(_c(f"  {title}", _BOLD, _CYAN))
    print_separator()


def _print_stage(n: int, label: str) -> None:
    """Print a numbered pipeline stage indicator."""
    print(f"  {_c(f'[{n}/5]', _DIM)} {label}")


# (ONLY display_result changed + indentation fixed)

def display_result(result):
    """Pretty-print an AnalysisResult to the terminal."""
    sev = result.severity

    print_section("📋  ANALYSIS SUMMARY")
    print(f"  File:          {_c(Path(result.file_path).name, _BOLD)}")
    print(f"  Log type:      {result.log_type.upper()}")
    print(f"  Analysed at:   {result.analysed_at}")
    print(f"  Events parsed: {_c(result.event_count, _BOLD)}")
    print(f"  Alerts raised: {_c(result.alert_count, _BOLD, _RED if result.alert_count else _GREEN)}")
    print(f"  Severity:      {_severity_colour(sev.severity)}  (score: {sev.score}/100)")
    print()
    print(f"  {_c(sev.summary, _DIM)}")

    # 🔗 ATTACK CHAIN
    if hasattr(result, "attack_chain_summary"):
        print_section("🔗  ATTACK CHAIN SUMMARY")
        print(f"  {_c(result.attack_chain_summary, _YELLOW)}")

    # ⚠️ IMPACT
    if hasattr(result, "impact_analysis"):
        print_section("⚠️  IMPACT ANALYSIS")

        impact = result.impact_analysis

        if isinstance(impact, dict):
            print(f"  {_c(impact.get('potential_impact', ''), _RED)}\n")

            if impact.get("recommended_action"):
                print(f"  {_c('Recommended Action:', _BOLD, _CYAN)}")
                print(f"  {_c(impact['recommended_action'], _GREEN)}")

    # Alerts
    if result.alerts:
        print_section(f"🚨  RULE-BASED ALERTS  ({len(result.alerts)})")
        for alert in result.alerts:
            print(
                f"  [{_c(alert['rule_id'], _MAGENTA)}] "
                f"{_c(alert['type'], _BOLD)}  —  "
                f"Confidence: {_confidence_colour(alert['confidence'])}  —  "
                f"Source IP: {_c(alert['source_ip'], _CYAN)}"
            )
            print(f"       {_c(alert['description'], _DIM)}")
            print()

    # MITRE
    if result.mitre_techniques:
        print_section(f"🛡️   MITRE ATT&CK MAPPING  ({len(result.mitre_techniques)} techniques)")
        for tech in result.mitre_techniques:
            print(
                f"  {_c(tech['technique_id'], _BOLD, _YELLOW)}  "
                f"{tech['name']:40s}  "
                f"Tactic: {_c(tech['tactic'], _CYAN)}"
            )
            print(f"       {_c(tech.get('url', ''), _DIM)}")

    # Top IPs
    if result.top_source_ips:
        print_section("🌐  TOP SOURCE IPs")
        for entry in result.top_source_ips[:8]:
            print(
                f"  {_c(entry['ip'], _CYAN):20s}  "
                f"{entry['event_count']:>5} events"
            )

    # AI
    print_section(f"🤖  AI ANALYSIS  ({'Ollama' if result.ai_available else 'UNAVAILABLE'})")
    print()
    if result.ai_available:
        for line in result.ai_analysis.splitlines():
            print(f"  {line}")
    else:
        print(f"  {_c(result.ai_analysis, _YELLOW)}")

    print()
    print_separator()


def display_multi_summary(results: list) -> None:  # noqa: ANN001
    """Print a summary table for multiple file analysis."""
    print_section("📊  MULTI-FILE ANALYSIS SUMMARY")
    header = f"  {'File':35s}  {'Events':>7}  {'Alerts':>6}  {'Severity':>10}  {'Score':>5}"
    print(_c(header, _BOLD))
    print_separator()
    for r in results:
        fname = Path(r.file_path).name[:34]
        sev_display = _severity_colour(r.severity.severity)
        print(
            f"  {fname:35s}  "
            f"{r.event_count:>7}  "
            f"{r.alert_count:>6}  "
            f"{sev_display:>10}  "
            f"{r.severity.score:>5}"
        )


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_analyse(args: argparse.Namespace) -> int:
    """Handle the 'analyse' subcommand."""
    from dotenv import load_dotenv
    load_dotenv()

    print_banner()

    # ── Resolve log file paths ───────────────────────────────────────────────
    file_paths: list[str] = []
    for pattern in args.files:
        p = Path(pattern)
        if "*" in str(p) or "?" in str(p):
            # Shell glob expansion (useful on Windows where the shell doesn't expand)
            matched = sorted(Path(".").glob(str(p)))
            if not matched:
                print(f"{_c('WARNING:', _YELLOW)} No files matched pattern: {pattern}")
            file_paths.extend(str(f) for f in matched if f.is_file())
        elif p.is_file():
            file_paths.append(str(p))
        else:
            print(f"{_c('ERROR:', _RED)} File not found: {pattern}")
            return 1

    if not file_paths:
        print(f"{_c('ERROR:', _RED)} No valid log files found.")
        return 1

    # ── Optional integrations ────────────────────────────────────────────────
    ip_enricher = None
    if not args.no_enrich:
        try:
            from app.integrations.abuseipdb import check_ip, is_api_configured
            if is_api_configured():
                ip_enricher = check_ip
                print(f"{_c('✔', _GREEN)} AbuseIPDB enrichment enabled.")
            else:
                print(
                    f"{_c('ℹ', _CYAN)} AbuseIPDB not configured "
                    f"(set ABUSEIPDB_API_KEY in .env) — skipping enrichment."
                )
        except ImportError:
            pass

    # ── Ollama pre-flight ────────────────────────────────────────────────────
    ai_enabled = not args.no_ai
    if ai_enabled:
        client = OllamaClient(model=args.model)
        if client.is_available():
            available_models = client.list_models()
            print(
                f"{_c('✔', _GREEN)} Ollama running  |  "
                f"Models: {', '.join(available_models[:5]) or 'none listed'}"
            )
            if not client.model_is_available():
                print(
                    f"{_c('⚠', _YELLOW)} Model '{args.model}' not installed — "
                    f"run: ollama pull {args.model}"
                )
        else:
            print(
                f"{_c('⚠', _YELLOW)} Ollama not running — "
                f"AI analysis disabled for this session.  (start with: ollama serve)"
            )

    # ── Ensure output directory exists ──────────────────────────────────────
    output_dir = Path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"{_c('ERROR:', _RED)} Cannot create output directory {output_dir}: {exc}")
        return 1

    # ── Run analysis ─────────────────────────────────────────────────────────
    if len(file_paths) == 1:
        print(f"\n{_c('▶  Analysing:', _BOLD)} {file_paths[0]}\n")

        _print_stage(1, "Parsing log file...")
        try:
            from app.core.analyzer import analyse_log_file, save_report
            result = analyse_log_file(
                file_path=file_paths[0],
                log_type=args.type,
                enable_ai=ai_enabled,
                ollama_model=args.model,
                ip_enricher=ip_enricher,
            )
        except FileNotFoundError as exc:
            print(f"\n{_c('ERROR:', _RED)} {exc}")
            return 1
        except Exception as exc:
            print(f"\n{_c('ERROR:', _RED)} Analysis failed: {exc}")
            if args.log_level == "DEBUG":
                import traceback
                traceback.print_exc()
            return 1

        display_result(result)

        report_path = save_report(result, output_dir)
        txt_path = report_path.with_suffix(".txt")

        print(f"\n{_c('✔ Reports saved:', _GREEN)}")
        print(f"    JSON  →  {report_path}")
        if txt_path.exists():
            print(f"    TEXT  →  {txt_path}")

        if args.dump_json:
            print()
            print(json.dumps(result.to_dict(), indent=2, default=str))

    else:
        print(f"\n{_c(f'▶  Analysing {len(file_paths)} log files...', _BOLD)}\n")
        from app.core.analyzer import analyse_multiple_files, save_report
        results = analyse_multiple_files(
            file_paths=file_paths,
            log_type=args.type,
            enable_ai=ai_enabled,
            ollama_model=args.model,
            ip_enricher=ip_enricher,
        )
        if not results:
            print(f"{_c('ERROR:', _RED)} All files failed to parse.")
            return 1

        display_multi_summary(results)

        print(f"\n{_c('Saving reports...', _DIM)}")
        for r in results:
            rp = save_report(r, output_dir)
            print(f"  {_c('✔', _GREEN)} {rp.name}")
        print(f"\n{_c('Reports saved to:', _GREEN)} {output_dir.resolve()}")

    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Check Ollama and AbuseIPDB status."""
    from dotenv import load_dotenv
    load_dotenv()

    print_banner()
    print_section("🔍  SYSTEM STATUS")

    client = OllamaClient(model=args.model)
    if client.is_available():
        models = client.list_models()
        print(f"  {_c('✔', _GREEN)} Ollama: RUNNING at {client.base_url}")
        print(f"       Available models: {', '.join(models) if models else 'none'}")
        if client.model_is_available():
            print(f"       Model '{args.model}': {_c('READY', _GREEN)}")
        else:
            print(f"       Model '{args.model}': {_c('NOT INSTALLED', _RED)} — run: ollama pull {args.model}")
    else:
        print(f"  {_c('✗', _RED)} Ollama: NOT RUNNING — start with: ollama serve")

    try:
        from app.integrations.abuseipdb import is_api_configured
        if is_api_configured():
            print(f"  {_c('✔', _GREEN)} AbuseIPDB: API key configured")
        else:
            print(f"  {_c('ℹ', _CYAN)} AbuseIPDB: Not configured (optional — set ABUSEIPDB_API_KEY in .env)")
    except ImportError:
        print(f"  {_c('ℹ', _CYAN)} AbuseIPDB module unavailable.")

    print()
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-assistant",
        description="AI-Powered SOC Assistant — Offline Log Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m app.cli analyse data/samples/ssh_bruteforce.log
  python -m app.cli analyse data/samples/sql_injection.log --type web
  python -m app.cli analyse logs/*.log --no-ai --output-dir reports/
  python -m app.cli status
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── analyse subcommand ──────────────────────────────────────────────────
    analyse_p = subparsers.add_parser("analyse", help="Analyse one or more log files")
    analyse_p.add_argument(
        "files", nargs="+", metavar="LOG_FILE",
        help="Path(s) to log file(s) to analyse (supports globs)",
    )
    analyse_p.add_argument(
        "--type", choices=["auto", "ssh", "web"], default="auto",
        help="Log type (default: auto-detect)",
    )
    analyse_p.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Ollama model to use (default: {DEFAULT_MODEL})",
    )
    analyse_p.add_argument(
        "--no-ai", action="store_true",
        help="Disable AI analysis (rule-based only)",
    )
    analyse_p.add_argument(
        "--no-enrich", action="store_true",
        help="Disable IP reputation enrichment",
    )
    analyse_p.add_argument(
        "--output-dir", default="outputs/reports",
        help="Directory for JSON report output (default: outputs/reports)",
    )
    analyse_p.add_argument(
        "--dump-json", action="store_true", dest="dump_json",
        help="Also print the full JSON result to stdout after analysis",
    )
    analyse_p.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Internal logging verbosity (default: WARNING)",
    )
    analyse_p.set_defaults(func=cmd_analyse)

    # ── status subcommand ───────────────────────────────────────────────────
    status_p = subparsers.add_parser("status", help="Check Ollama and integration status")
    status_p.add_argument("--model", default=DEFAULT_MODEL)
    status_p.set_defaults(func=cmd_status)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = getattr(args, "log_level", "WARNING")
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
