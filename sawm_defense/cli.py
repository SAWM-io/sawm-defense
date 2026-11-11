"""The same defense service in a terminal, without GUI dependencies at startup."""
import argparse
import getpass
import json
import signal
import sys
import time
from pathlib import Path


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def parser():
    p = argparse.ArgumentParser(prog="sawm-defense", description="SAWM Defense — application et agent CLI")
    p.add_argument("--version", action="version", version="SAWM Defense 0.1.0")
    p.add_argument("--state-dir", type=Path, help="Profil local distinct (configuration, journal et file Cloud)")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("gui", help="Ouvrir l'application")
    sub.add_parser("status", help="État et dernières observations")
    sub.add_parser("doctor", help="Vérifier les capacités réellement disponibles")
    sub.add_parser("once", help="Un échantillonnage local sans appel Cloud")
    watch = sub.add_parser("watch", help="Surveillance continue jusqu'à Ctrl+C")
    watch.add_argument("--seconds", type=float, default=0, help="Durée bornée pour un essai (0 = continu)")
    config = sub.add_parser("configure", help="Configurer le profil ; la clé n'est jamais un argument")
    config.add_argument("--base-url")
    config.add_argument("--space")
    config.add_argument("--entity")
    config.add_argument("--watch-path", action="append")
    config.add_argument("--cloud", action=argparse.BooleanOptionalAction, default=None)
    config.add_argument("--upload-events", action=argparse.BooleanOptionalAction, default=None)
    config.add_argument("--cloud-per-hour", type=int)
    config.add_argument("--prompt-key", action="store_true")
    config.add_argument("--session-key", action="store_true", help="Clé en mémoire seulement, pour cette invocation")
    config.add_argument("--auto-quarantine", action=argparse.BooleanOptionalAction, default=None)
    sub.add_parser("check-cloud", help="Vérifier l'accès Cloud (consomme le budget d'opérations)")
    scan = sub.add_parser("scan", help="Analyser un fichier du périmètre avec l'antivirus installé")
    scan.add_argument("path", type=Path)
    sub.add_parser("inventory", help="Inventorier les logiciels installés")
    analyze = sub.add_parser("analyze", help="Demander à SAWM une proposition sur les événements")
    analyze.add_argument("--event-id")
    chat = sub.add_parser("chat", help="Échanger avec SAWM, contexte local seulement si autorisé")
    chat.add_argument("message", nargs="?")
    act = sub.add_parser("act", help="Action locale précise, limitée par le périmètre configuré")
    act.add_argument("action", choices=["observe", "quarantine", "terminate", "block_ip"])
    act.add_argument("event_id")
    act.add_argument("--approve", action="store_true", help="Autorisation humaine explicite de cette seule action")
    restore = sub.add_parser("restore", help="Restaurer une quarantaine ou retirer un blocage enregistré")
    restore.add_argument("action_id")
    restore.add_argument("--approve", action="store_true")
    export = sub.add_parser("report", help="Exporter un rapport HTML ou JSON")
    export.add_argument("path", type=Path)
    startup = sub.add_parser("startup", help="Service supervisé de l'utilisateur, activé explicitement")
    startup.add_argument("operation", choices=["plan", "install", "remove"])
    startup.add_argument("--approve", action="store_true")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command in (None, "gui"):
        from .gui import main as gui
        gui(args.state_dir)
        return 0
    from .service import AgentService
    from .autorun import startup_plan
    agent = None
    try:
        agent = AgentService(args.state_dir)
        result = None
        if args.command == "configure":
            patch = {}
            for arg, key in (("base_url", "cloud_base_url"), ("space", "space_id"), ("entity", "entity_id"),
                             ("watch_path", "monitor_paths"), ("cloud", "cloud_enabled"),
                             ("upload_events", "cloud_upload_enabled"), ("cloud_per_hour", "cloud_per_hour")):
                value = getattr(args, arg)
                if value is not None:
                    patch[key] = value
            if args.auto_quarantine is not None:
                current = agent.settings()["automatic_actions"]
                patch["automatic_actions"] = [a for a in current if a != "quarantine"] + (["quarantine"] if args.auto_quarantine else [])
            key = getpass.getpass("Clé API (non affichée) : ") if args.prompt_key else None
            result = agent.save_settings(patch, api_key=key, persist_key=not args.session_key)
        elif args.command == "once":
            result = agent.tick()
        elif args.command in ("doctor", "status"):
            if args.command == "doctor":
                agent.tick()
            result = agent.status()
        elif args.command == "watch":
            end = time.monotonic() + args.seconds if args.seconds > 0 else None
            stopping = [False]
            def stop(*_):
                stopping[0] = True
            signal.signal(signal.SIGINT, stop)
            signal.signal(signal.SIGTERM, stop)
            result = agent.start()
            emit(result)
            if result["status"] != "completed":
                return 2
            while not stopping[0] and (end is None or time.monotonic() < end):
                time.sleep(.2)
            result = agent.stop()
        elif args.command == "check-cloud":
            result = agent.check_connection()
        elif args.command == "scan":
            result = agent.scan(args.path)
        elif args.command == "inventory":
            result = agent.inventory()
        elif args.command == "analyze":
            result = agent.analyze(args.event_id)
        elif args.command == "chat":
            result = agent.chat(args.message or input("Vous : "))
        elif args.command == "act":
            result = agent.act(args.action, args.event_id, approved=args.approve)
        elif args.command == "restore":
            result = agent.restore(args.action_id, approved=args.approve)
        elif args.command == "report":
            result = {"status": "completed", "path": agent.export_report(args.path)}
        elif args.command == "startup":
            if args.operation == "plan":
                result = startup_plan(agent._command(), agent.state_dir)
            elif not args.approve:
                result = {"status": "denied", "reason": "Utilisez --approve après avoir consulté startup plan."}
            else:
                result = agent.install_startup() if args.operation == "install" else agent.remove_startup()
        emit(result)
        return 2 if isinstance(result, dict) and result.get("status") in ("denied", "error", "unsupported", "unavailable") else 0
    except (KeyboardInterrupt, EOFError):
        return 130
    except Exception as exc:
        # Native exceptions could include URLs or headers. Keep CLI errors safe.
        message = str(exc) if isinstance(exc, ValueError) else "Opération non terminée ; consultez les capacités et le journal local."
        emit({"status": "error", "error_type": type(exc).__name__, "message": message})
        return 1
    finally:
        if agent:
            agent.close()
