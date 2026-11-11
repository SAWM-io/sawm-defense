# Validation — 11 novembre 2026

## Résultats vérifiés

**92 tests réussis** sur macOS Apple Silicon, Python 3.12.14 et Tk 9.0.4.

Les essais couvrent :

- Création/modification/suppression de vrais fichiers temporaires, empreintes SHA256 et exclusion des liens symboliques.
- Vraie quarantaine et restauration d’un fichier inoffensif. La détection utilisée pour ce test est une fixture contrôlée ; ce n’est pas un test sur malware réel.
- Arrêt réel d’un sous-processus de test autorisé, refus d’un PID périmé ou d’une cible hors périmètre.
- Persistance après redémarrage, file Cloud idempotente, file de scans de 120 événements et absence d’effacement de leur preuve pendant la rétention.
- Panne et reprise Cloud, réponses incomplètes, ACK partiel, quotas concurrents.
- Révocation d’une permission et du partage de contexte depuis une autre instance, clés séparées par destination et rotation de clé.
- Refus de commandes arbitraires, de cibles inventées et d’une action automatique fondée seulement sur un pic CPU.
- Intégrité du journal, export HTML échappé, absence de clé dans les rapports et la configuration.
- Interface Tk construite et contrôlée ; travaux hors du thread graphique et annulation d’une action humaine respectée.

L’application Mac construite avec PyInstaller a été ouverte visuellement : formulaire de configuration, démarrage et arrêt, mesures CPU/RAM changeantes et graphe réel contrôlés.

## Niveau des preuves Cloud et plateformes

Les tests Cloud emploient **le vrai SDK public** avec `httpx.MockTransport`. Ils vérifient les requêtes, l’idempotence, TSST, ODVL et les réponses SAWM. Aucun compte client ni clé réelle n’a été utilisé dans cette campagne : une validation Cloud réelle de cette nouvelle application reste à faire après sa configuration.

Les règles UFW, Windows Firewall et les services de démarrage sont testés par contrôles et commandes simulées. Aucun pare-feu ni service permanent du poste de développement n’a été modifié. Windows et Linux nécessitent une campagne native avant distribution industrielle.

Aucun résultat ne démontre une couverture complète des malwares, une résistance à root hostile, une interception universelle des téléchargements ou une certification réglementaire.

## Reproduire

```bash
python -m pytest -q
python -m sawm_defense --state-dir /chemin/jetable doctor
python -m sawm_defense --state-dir /chemin/jetable watch --seconds 10
python packaging/build.py
```

## Exécutable Mac autonome

Le CLI du paquet `.app` a également été exécuté hors du code source sur un profil temporaire : modification et suppression détectées, quarantaine manuelle puis restauration réelles, 6 événements et 2 actions enregistrés, journal valide et rapport HTML exporté. Aucun Cloud, moteur antivirus réel ni pare-feu n'a été utilisé dans cet essai.

Preuve structurée : [packaged-macos-validation.json](packaged-macos-validation.json).

Une analyse statique Bandit a été effectuée : aucune alerte moyenne ou élevée restante dans le code du client. Les appels système contrôlés restent des points de revue explicites ; ce résultat ne constitue pas une certification.
