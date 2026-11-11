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
    p.add_argument("--version", action="version", version="SAWM Defense 0.2.0")
    p.add_argument("--state-dir", type=Path, help="Profil local distinct (configuration, journal et file Cloud)")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("gui", help="Ouvrir l'application")
    sub.add_parser("status", help="État et dernières observations")
    sub.add_parser("doctor", help="Vérifier les capacités réellement disponibles")
    sub.add_parser("once", help="Un échantillonnage local sans appel Cloud")
    watch = sub.add_parser("watch", help="Surveillance continue jusqu'à Ctrl+C")
    watch.add_argument("--seconds", type=float, default=0, help="Durée bornée pour un essai (0 = continu)")
    watch.add_argument("--prompt-key", action="store_true", help="Saisir une clé masquée gardée uniquement pendant ce service")
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
    for name in ("protect-downloads", "automatic-scan", "notifications", "autonomous-analysis", "auth-journal", "auto-block-auth", "auto-terminate", "auto-block-ip"):
        config.add_argument("--" + name, action=argparse.BooleanOptionalAction, default=None)
    for name in ("protected-ip", "auth-log", "kernel-audit-path", "allow-process", "allow-ip"):
        config.add_argument("--" + name, action="append")
    config.add_argument("--auto-block-seconds", type=int)
    sub.add_parser("check-cloud", help="Vérifier l'accès Cloud (consomme le budget d'opérations)")
    scan = sub.add_parser("scan", help="Inspection statique locale et antivirus, s'il est disponible")
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
    order = sub.add_parser("order", help="Soumettre une mission persistante au service actif")
    order.add_argument("kind", choices=["scan", "inventory", "analyze", "act", "restore", "report"])
    order.add_argument("--path")
    order.add_argument("--event-id")
    order.add_argument("--action", choices=["observe", "quarantine", "terminate", "block_ip"])
    order.add_argument("--action-id")
    order.add_argument("--approve", action="store_true")
    order.add_argument("--idempotency-key")
    sub.add_parser("orders", help="Voir les missions et leurs reçus")
    alerts = sub.add_parser("notifications", help="Voir ou accuser réception des alertes locales")
    alerts.add_argument("--ack")
    kernel = sub.add_parser("kernel", help="Plan ou installation bornée de règles audit Linux")
    kernel.add_argument("operation", choices=["plan", "install"])
    kernel.add_argument("--approve", action="store_true")
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
                             ("upload_events", "cloud_upload_enabled"), ("cloud_per_hour", "cloud_per_hour"),
                             ("protect_downloads", "protect_downloads"), ("automatic_scan", "automatic_scan_enabled"),
                             ("notifications", "notifications_enabled"), ("autonomous_analysis", "autonomous_analysis_enabled"),
                             ("auth_journal", "auth_journal_enabled"), ("auto_block_auth", "autoblock_auth_ips"),
                             ("auto_block_seconds", "auto_block_seconds"), ("protected_ip", "protected_remote_ips"),
                             ("auth_log", "auth_log_paths"), ("kernel_audit_path", "kernel_audit_paths"),
                             ("allow_process", "allowed_process_paths"), ("allow_ip", "allowed_remote_ips")):
                value = getattr(args, arg)
                if value is not None:
                    patch[key] = value
            current = agent.settings()["automatic_actions"]
            for arg, action in (("auto_quarantine", "quarantine"), ("auto_terminate", "terminate"), ("auto_block_ip", "block_ip")):
                if getattr(args, arg) is not None:
                    current = [a for a in current if a != action] + ([action] if getattr(args, arg) else [])
            patch["automatic_actions"] = current
            key = getpass.getpass("Clé API (non affichée) : ") if args.prompt_key else None
            result = agent.save_settings(patch, api_key=key, persist_key=not args.session_key)
        elif args.command == "once":
            result = agent.tick()
        elif args.command in ("doctor", "status"):
            if args.command == "doctor":
                agent.tick()
            result = agent.status()
        elif args.command == "watch":
            if args.prompt_key:
                agent.save_settings({}, api_key=getpass.getpass("Clé API de la session (non affichée) : "), persist_key=False)
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
        elif args.command == "orders":
            result = agent.orders.list()
        elif args.command == "order":
            payload = {key: getattr(args, key) for key in ("path", "event_id", "action", "action_id") if getattr(args, key) is not None}
            result = agent.submit_order(args.kind, payload, approved=args.approve, idempotency_key=args.idempotency_key)
        elif args.command == "notifications":
            result = agent.acknowledge_notification(args.ack) if args.ack else agent.notifications.list()
        elif args.command == "kernel":
            from .kernel import audit_plan, install_audit
            result = audit_plan(agent.settings(), agent.state_dir) if args.operation == "plan" else install_audit(agent.settings(), agent.state_dir, approved=args.approve)
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
