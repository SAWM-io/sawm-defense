"""Local authorization. Cloud observations and proposals cannot expand grants."""
from datetime import datetime, timezone

ACTIONS = frozenset({"observe", "quarantine", "terminate", "block_ip"})
MAX_EVENT_AGE_SECONDS = 300


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
    # Only the scanner's locally-created record is eligible. LLM confidence,
    # CPU use, filenames and remote testimony cannot satisfy this condition.
    if (event.get("kind") != "antivirus_detection" or
            details.get("verification_origin") != "local_scanner" or
            details.get("scan_status") != "detected" or
            not details.get("sha256") or not details.get("engine")):
        return False, "Indice à examiner ; aucune détection antivirus locale vérifiée."
    # The current scanner proves a file, not its author or a remote peer.
    if action != "quarantine":
        return False, "L'attribution de cette détection au processus ou à l'IP n'est pas établie."
    return True, "Détection locale vérifiée et quarantaine autorisée."
