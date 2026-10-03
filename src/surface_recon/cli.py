import argparse
from pathlib import Path
import sys
import time
import webbrowser

from .assessment import assess_targets
from .results import render_assessment, render_surface_map, write_surface_report_html


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
    parser = argparse.ArgumentParser(
        prog="surface-recon",
        description="Autonomous, evidence-first reconnaissance of authorized attack surface.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    recon = sub.add_parser(
        "recon",
        help="Run autonomous reconnaissance; Surface_Recon may use safe available capabilities.",
        description="Recon an authorized target autonomously; owned capabilities lead and optional tools may enrich evidence.",
        epilog="Example: surface-recon recon http://127.0.0.1:3000",
    )
    recon.add_argument("targets", nargs="+", help="Cualquier objetivo autorizado: URL, host, red, archivo, directorio, repositorio u otro target.")
    recon.add_argument("--no-open", action="store_true", help="No abrir automáticamente el informe HTML.")
    recon.add_argument("--core-only", action="store_true", help="Desactivar extensiones externas; útil para benchmark del core.")

    assess = sub.add_parser(
        "assess",
        help="Run the core plus available optional extensions.",
        description="Assess authorized targets; external tooling may enrich core evidence.",
        epilog="Example: surface-recon assess https://example.com 127.0.0.1 ./artifact",
    )
    assess.add_argument(
        "targets",
        nargs="+",
        help="Authorized targets such as URLs, hosts/IPs, or local paths.",
    )
    assess.add_argument(
        "--core-only",
        action="store_true",
        help="Disable all external tool extensions.",
    )

    args = parser.parse_args()

    if args.command == "recon":
        started = time.monotonic()
        mode = "core" if args.core_only else "core + capacidades pertinentes del entorno"
        print(f"Surface_Recon: iniciando {mode} sobre {len(args.targets)} objetivo(s)...", flush=True)
        print("Surface_Recon: la salida final distinguirá evidencia, hipótesis, hallazgos y cobertura no evaluada.", flush=True)
        result = assess_targets(args.targets, use_extensions=not args.core_only)
        print(f"Surface_Recon: reconocimiento completado en {time.monotonic() - started:.1f}s; generando informe...", flush=True)
        print(render_surface_map(result))
        report = write_surface_report_html(Path("reports") / "surface-recon-latest.html", result).resolve()
        print(f"\nINFORME VISUAL: {report}")
        if not args.no_open:
            webbrowser.open(report.as_uri())
    elif args.command == "assess":
        result = assess_targets(args.targets, use_extensions=not args.core_only)
        print(render_assessment(result))
    else:
        return 1
    if result.status.value == "failed":
        return 1
    # "recon" is successful when the owned core produced a map; explicit gaps
    # remain visible in the output and are not treated as a CLI execution error.
    if args.command == "assess" and result.status.value == "partial":
        return 2
    return 0
