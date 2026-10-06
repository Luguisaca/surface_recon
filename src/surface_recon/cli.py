import argparse
from pathlib import Path
import sys
import time
import webbrowser

from .assessment import assess_targets
from .results import render_assessment, render_surface_map, write_surface_report_html
from .controls import ReconControls
from .reporting import human_error, continuation_targets


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
        epilog="Example: surface-recon recon --authorized http://127.0.0.1:3000",
    )
    recon.add_argument("targets", nargs="*", help="Cualquier objetivo autorizado: URL, host, red, archivo, directorio, repositorio u otro target.")
    recon.add_argument("--no-open", action="store_true", help="No abrir automáticamente el informe HTML.")
    recon.add_argument("--core-only", action="store_true", help="Desactivar extensiones externas; útil para benchmark del core.")
    recon.add_argument("--authorized", action="store_true", help="Confirmo que tengo autorización para evaluar todos los objetivos enviados.")
    recon.add_argument("--continue-from", type=Path, help="Profundizar el alcance original de un export JSON; requiere --authorized de nuevo.")
    recon.add_argument("--output", type=Path, default=Path("reports/surface-recon-latest.html"), help="Informe HTML y exports JSON/CSV adyacentes.")

    assess = sub.add_parser(
        "assess",
        help="Technical/automation assessment output; no visual report.",
        description="Technical assessment for automation/debugging; prints detailed text and does not create the visual report.",
        epilog="For normal human use and a visual report, use: surface-recon recon --authorized TARGET",
    )
    assess.add_argument("targets", nargs="+", help="Authorized targets such as URLs, hosts/IPs, or local paths.")
    assess.add_argument("--core-only", action="store_true", help="Disable all external tool extensions.")
    assess.add_argument("--authorized", action="store_true", help="Confirm authorization for every submitted target.")

    serve = sub.add_parser(
        "serve",
        help="Open the local interactive Surface_Recon interface.",
        description="Serve the local HUMAN-QA interface on loopback only; explicit target authorization is required.",
    )
    serve.add_argument("--port", type=int, default=8041, help="Loopback TCP port (default: 8041).")
    serve.add_argument("--no-open", action="store_true", help="Do not open the local interface in the browser.")
    serve.add_argument("--core-only", action="store_true", help="Disable external extensions for UI assessments.")

    for command in (recon, assess):
        command.add_argument("--mode", "--profile", choices=["auto", "passive", "active", "balanced", "deep"], default="auto", help="passive: solo local; active: core de red acotado; auto/balanced: selección por cobertura; deep: amplía presupuesto web.")
        command.add_argument("--intensity", choices=["low", "normal"], default="normal", help="low: 10 solicitudes web/60s, pausa y sin providers; normal: 30/120s; deep normal: sin tope de solicitudes/300s. Los adapters conservan sus límites.")
        command.add_argument("--include-provider", action="append", default=[], help="Filtro avanzado del catálogo verificado; no fuerza ejecución sin evidencia pertinente.")
        command.add_argument("--exclude-provider", action="append", default=[], help="Excluir provider de la selección automática.")
    args = parser.parse_args()

    if args.command in {"recon", "assess"} and not args.authorized:
        print(
            "Surface_Recon: autorización requerida. Usa --authorized únicamente cuando tengas permiso para evaluar todos los objetivos.",
            file=sys.stderr, flush=True,
        )
        return 3

    options = {}
    if args.command in {"recon", "assess"}:
        controls = ReconControls(args.mode, args.intensity, tuple(args.include_provider), tuple(args.exclude_provider))
        if controls != ReconControls():
            options["controls"] = controls
        if args.command == "recon" and args.continue_from:
            if args.targets:
                parser.error("Usa objetivos o --continue-from, no ambos.")
            try:
                args.targets = continuation_targets(args.continue_from)
                if args.mode == "auto":
                    options["controls"] = ReconControls("deep", args.intensity, tuple(args.include_provider), tuple(args.exclude_provider))
                print("Continuación segura: se repite/profundiza el alcance original, sin autorizar referencias externas ni ejecutar recetas invasivas.")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                print("Surface_Recon: " + human_error(exc), file=sys.stderr)
                return 3
        if not args.targets:
            parser.error("Se requiere un objetivo o --continue-from.")

    if args.command == "recon":
        started = time.monotonic()
        mode = "core" if args.core_only else "core + capacidades pertinentes del entorno"
        print(f"Surface_Recon: iniciando {mode} sobre {len(args.targets)} objetivo(s)...", flush=True)
        print("Surface_Recon: la salida final distinguirá evidencia, hipótesis, hallazgos y cobertura no evaluada.", flush=True)
        try:
            result = assess_targets(
                args.targets, use_extensions=not args.core_only,
                progress=lambda message: print(f"Surface_Recon: {message}", flush=True),
                **options,
            )
        except (ValueError, OSError) as exc:
            print("Surface_Recon: " + human_error(exc), file=sys.stderr, flush=True)
            return 3
        except KeyboardInterrupt:
            print("", file=sys.stderr)
            print("Surface_Recon: reconocimiento cancelado por el usuario.", file=sys.stderr, flush=True)
            return 130
        print(f"Surface_Recon: reconocimiento completado en {time.monotonic() - started:.1f}s; generando informe...", flush=True)
        print(render_surface_map(result))
        report = write_surface_report_html(args.output, result).resolve()
        exports = (args.output.with_suffix(".json"), args.output.with_suffix(".csv"))
        print("EXPORTS JSON + CSV: " + " · ".join(str(path.resolve()) for path in exports))
        print("")
        print(f"INFORME VISUAL: {report}")
        if not args.no_open:
            webbrowser.open(report.as_uri())
    elif args.command == "assess":
        started = time.monotonic()
        print(f"Surface_Recon: iniciando evaluación de {len(args.targets)} objetivo(s)...", flush=True)
        try:
            result = assess_targets(
                args.targets, use_extensions=not args.core_only,
                progress=lambda message: print(f"Surface_Recon: {message}", flush=True),
                **options,
            )
        except (ValueError, OSError) as exc:
            print("Surface_Recon: " + human_error(exc), file=sys.stderr, flush=True)
            return 3
        except KeyboardInterrupt:
            print("", file=sys.stderr)
            print("Surface_Recon: evaluación cancelada por el usuario.", file=sys.stderr, flush=True)
            return 130
        print(f"Surface_Recon: evaluación completada en {time.monotonic() - started:.1f}s.", flush=True)
        print(render_assessment(result))
    elif args.command == "serve":
        from .web import serve_local
        serve_local(port=args.port, open_browser=not args.no_open, use_extensions=not args.core_only)
        return 0
    else:
        return 1

    if result.status.value == "failed":
        return 1
    if args.command == "assess" and result.status.value == "partial":
        return 2
    return 0
