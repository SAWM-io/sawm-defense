"""Local authorization. Cloud observations and proposals cannot expand grants."""
from datetime import datetime, timezone
import ipaddress

ACTIONS = frozenset({"observe", "quarantine", "terminate", "block_ip"})
MAX_EVENT_AGE_SECONDS = 300


def trusted_auth_event(event, config):
    """A repeated failure window from the local kernel-attributed sshd journal only."""
    d = event.get("details", {})
    producer = d.get("producer", {})
    try:
        ip = ipaddress.ip_address(d.get("remote_ip"))
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(d["last_failure_at"].replace("Z", "+00:00"))).total_seconds()
        return (event.get("kind") == "auth_bruteforce" and d.get("verified_local") is True
                and d.get("verification_origin") == "local_journald" and d.get("source_kind") == "journald"
                and str(producer.get("_UID")) == "0" and producer.get("_COMM") in {"sshd", "sshd-session"}
                and producer.get("_EXE") in {"/usr/sbin/sshd", "/usr/sbin/sshd-session", "/usr/lib/openssh/sshd-session", "/usr/libexec/sshd-session", "/usr/libexec/openssh/sshd-session"}
                and producer.get("_TRANSPORT") == "syslog"
                and type(d.get("failure_count")) is int
                and d["failure_count"] >= config.get("auth_failure_threshold", 5)
                and type(d.get("window_seconds")) is int
                and d["window_seconds"] <= config.get("auth_window_seconds", 300)
                and 0 <= age <= min(config.get("auth_window_seconds", 300), MAX_EVENT_AGE_SECONDS)
                and isinstance(d.get("evidence_ids"), list) and len(set(d["evidence_ids"])) >= config.get("auth_failure_threshold", 5)
                and ip.is_global and str(ip) not in config.get("protected_remote_ips", []))
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def trusted_network_policy_event(event, config):
    """Only a fresh OS socket violating an explicit, still-current IP policy.

    These fields are created by the local collector/service. Remote JSON is not
    an event-ingestion API and cannot establish this provenance.
    """
    d = event.get("details", {})
    try:
        ip = str(ipaddress.ip_address(d.get("remote_ip")))
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(d["observed_at"].replace("Z", "+00:00"))).total_seconds()
        return (config.get("network_security_enabled", True) is True
                and config.get("autoblock_network_policy") is True
                and event.get("kind") == "network_policy_violation"
                and d.get("verified_local") is True and d.get("verification_origin") == "local_psutil_socket"
                and d.get("policy_violation") is True and d.get("policy_rule") == "denied_remote_ips"
                and d.get("policy_value") == ip
                and ip in config.get("denied_remote_ips", []) and ip in config.get("allowed_remote_ips", [])
                and ip not in config.get("protected_remote_ips", []) and ipaddress.ip_address(ip).is_global
                and type(d.get("remote_port")) is int and 1 <= d["remote_port"] <= 65535
                and 0 <= age <= 30 and isinstance(d.get("evidence_ids"), list)
                and bool(d["evidence_ids"]) and all(isinstance(v, str) and len(v) == 64 for v in d["evidence_ids"]))
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def authorize(action, event, config, *, approved=False):
    if action not in ACTIONS:
        return False, "Action inconnue : aucune commande libre n'est exécutée."
    if action == "observe":
        return True, "Observation uniquement."
    if not event:
        return False, "Preuve locale introuvable."
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))).total_seconds()
    except (ValueError, KeyError, TypeError):
        return False, "Date de la preuve invalide."
    if age < -5 or age > MAX_EVENT_AGE_SECONDS:
        return False, "Preuve périmée : observer ou analyser à nouveau la cible."
    if approved:
        return True, "Approbation explicite ; les limites de cible restent contrôlées."
    if action not in config.get("automatic_actions", []):
        return False, "Cette action demande une confirmation humaine."
    details = event.get("details", {})
    if action == "block_ip" and trusted_network_policy_event(event, config):
        return True, "Socket OS récent vers une IP interdite ; blocage de cette cible explicitement autorisé."
    if action == "block_ip" and trusted_auth_event(event, config):
        return True, "Échecs SSH attribués à sshd local, seuil dépassé et blocage autorisé."
    # Only the scanner's locally-created record is eligible. LLM confidence,
    # CPU use, filenames and remote testimony cannot satisfy this condition.
    if (event.get("kind") not in {"antivirus_detection", "antivirus_process_detection"} or
            details.get("verification_origin") != "local_scanner" or
            details.get("scan_status") != "detected" or
            not details.get("sha256") or not details.get("engine")):
        return False, "Indice à examiner ; aucune détection antivirus locale vérifiée."
    # The current scanner proves a file, not its author or a remote peer.
    if action == "terminate" and event.get("kind") == "antivirus_process_detection":
        if (details.get("exe_sha256") == details["sha256"] and details.get("exe") == details.get("path")
                and details.get("pid") and details.get("create_time")):
            return True, "Exécutable détecté lié à une identité de processus ; périmètre revérifié avant arrêt."
    if action != "quarantine" or event.get("kind") != "antivirus_detection":
        return False, "L'attribution de cette détection au processus ou à l'IP n'est pas établie."
    return True, "Détection locale vérifiée et quarantaine autorisée."
