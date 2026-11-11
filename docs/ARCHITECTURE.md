# Architecture du client SAWM Defense — 0.2

Le même `AgentService` sert la CLI et l’application Tkinter. La collecte, les analyses Cloud, les inspections de fichiers, les réponses locales, les missions et les notifications ont des workers séparés. Les appels à l’interface graphique s’exécutent hors du thread Tk ; seuls les rendus reviennent sur ce thread. Une seconde surveillance du même profil est refusée par un verrou système.

## Composants et frontières

| Module | Rôle |
| --- | --- |
| `platforms.py` | Échantillons bornés des fichiers, ressources, processus et connexions visibles. N’accorde aucun privilège. |
| `downloads.py` | Résolution du dossier Téléchargements et périmètre effectif ; stabilité d’un fichier avant analyse, avec traitement particulier des téléchargements partiels. |
| `file_inspection.py` | Inspection structurelle bornée sans exécuter le fichier. Les anomalies et contrôles incomplets restent distincts d’une détection antivirus. |
| `antivirus.py` | Intégration des moteurs à signatures présents. Aucun jugement LLM n’est présenté comme un résultat antivirus. |
| `security_sensors.py` | Journaux SSH, curseurs persistants, déduplication et fenêtre temporelle ; distinction des textes importés et des métadonnées système vérifiées. |
| `kernel.py` | Plan et installation explicites de règles audit Linux limitées aux répertoires choisis. Les événements auditd restent consultables via les outils natifs ; leur import dans l’application n’est pas réalisé. |
| `storage.py` | Événements, journal chaîné, files persistantes, compteur d’opérations Cloud et réservation des effets automatiques. |
| `orders.py` | Missions typées, demandeur local, clé d’idempotence, états, réservation temporaire d’exécution et reprise contrôlée après interruption. |
| `notifications.py` | Boîte d’alertes persistante et tentative de notification native, séparées de l’accusé de lecture. |
| `cloud.py` | SDK public : ingestion Basira, rappel TSST, classement ODVL consultatif et tour SAWM complet. JSON des propositions validé. |
| `policy.py` | Autorité locale, fraîcheur et provenance des preuves, critères d’automatisation. Le Cloud ne peut pas élargir les droits. |
| `actions.py` | Liste fermée d’interventions, vérification des cibles, reçus, résultats et retours arrière ciblés. |
| `secrets.py` | Trousseau système et clés liées à la destination ; aucun fichier `.env` distribué. |
| `autorun.py` | Service utilisateur supervisé, installation explicite et refus de remplacer un service tiers. |

Les moteurs privés Basira, TSST, ODVL et SAWM demeurent dans le Cloud. Le client contient leur contrat d’API et les contrôles locaux de sécurité, pas une copie de ces moteurs.

## Une alerte sans attendre une question

1. La veille prélève les observations disponibles et les conserve avec un identifiant.
2. Les nouveaux fichiers ou modifications admissibles entrent dans la file d’inspection. Le service attend une stabilité de taille, inode et horodatages ; un fichier encore en transfert n’est pas présenté comme entièrement téléchargé.
3. Les signaux pertinents alimentent la boîte d’alertes. Le système tente une notification native lorsque l’opérateur l’a activée ; la disponibilité réelle du mécanisme et le résultat sont affichés.
4. Si les autorisations de partage, les accès et le budget le permettent, SAWM analyse les observations en arrière-plan. Basira conserve le contexte, TSST rappelle les précédents autorisés, ODVL peut les réordonner. Un résultat ODVL qui change l’ensemble des preuves est écarté.
5. Une proposition passe par l’autorité locale, puis par la vérification actuelle de la cible. Le reçu distingue une action refusée, échouée ou exécutée.

Les constats, hypothèses, justifications synthétiques, permissions et effets sont séparés. L’application ne demande ni n’expose de raisonnement interne privé. Les textes externes restent des données, même s’ils contiennent des instructions adressées au modèle.

## Ce que signifie l’autonomie

La collecte locale, l’inspection et les notifications n’attendent pas un échange de chat. Les interventions automatiques restent un mandat précis, jamais une permission générale de contrôler la machine.

- **Quarantaine** : détection du moteur local, empreinte actuelle et périmètre autorisé ; exclusions protégées.
- **Arrêt** : exécutable autorisé, preuve antivirus attribuée, utilisateur, PID, date de création, chemin et empreinte revérifiés. Pas d’arrêt fondé seulement sur la consommation CPU.
- **Blocage IP** : cible publique autorisée et preuve admissible. Le mode SSH peut couvrir des IP attribuées à des échecs répétés par un journal système fiable. Les adresses protégées, destinations Cloud et résolveurs vérifiés sont exclus.
- **Revue humaine** : indices structurels, provenances insuffisantes, droits manquants ou effets incertains restent visibles. Une proposition peut être refusée même si le modèle est très confiant.

Le service marque une intervention automatique comme engagée avant de la lancer : une interruption ne conduit pas à la répéter aveuglément. Une reprise nécessitant une décision humaine conserve ses preuves et son reçu.

Les règles IP automatiques portent une échéance persistante. Leur retrait est exécuté par le service et contrôlé ; après un arrêt, le service rattrape les échéances à sa reprise. Ce n’est pas un minuteur UFW ou Windows indépendant de l’agent. La présence de règles ne prouve pas l’arrêt effectif de tous les flux établis : l’effet réseau doit être mesuré.

## Missions et dialogue

La liste de missions est fermée : scan, inventaire, analyse, rapport, action et restauration. La demande conserve l’identité de la session locale, les paramètres validés, l’approbation éventuelle et le résultat. Les missions périmées ou interrompues sont distinguées des réussites ; le type d’action détermine si une reprise automatique est admissible.

Le chat sert à expliquer et à demander un bilan. Il ne traduit pas une phrase libre en commande shell. Une demande de scan ou de rapport passe par les missions typées ; une intervention manuelle demande une approbation explicite et conserve les mêmes vérifications de cible.

## Données, secrets et mode dégradé

La clé ne figure ni dans les arguments du programme, ni dans les réglages ni dans les rapports. Elle est liée à la destination Cloud. Le partage de métadonnées est un consentement distinct du dialogue ; les fichiers ne sont pas automatiquement téléversés en intégralité. Le connecteur borne et filtre le contexte, puis masque les occurrences littérales de la clé.

Les appels Cloud utilisent un budget durable d’opérations, un verrou entre processus et des clés d’idempotence à l’ingestion. Un dépôt n’est retiré de la file qu’après réception confirmée. Une erreur ou un quota épuisé ne remplace pas le résultat par une réponse inventée.

Les files locales conservent le travail en attente. La rétention préserve les preuves nécessaires à ces files ; il faut donc superviser l’espace disque pendant une panne prolongée. Une chaîne locale détecte des incohérences, mais ne rend pas l’hôte inviolable face à son administrateur.

## Interfaces système et limites

L’agent fonctionne en espace utilisateur avec les droits accordés à son compte. Les accès au noyau passent par des interfaces système et outils natifs autorisés, pas par un modèle de langage exécuté en mode noyau. Les règles audit Linux sont installées seulement après examen et approbation, sans élévation silencieuse ni remise à zéro globale. Voir [KERNEL.md](KERNEL.md).

La collecte n’est pas exhaustive. Des actions très courtes peuvent échapper au sondage ; la visibilité réseau dépend de l’OS ; les téléchargements ne sont pas tous interceptés avant exécution ; une inspection de binaire ne fournit pas automatiquement son code source. Windows et Linux demandent des essais natifs, distincts des tests de commandes simulées. Les clés réelles et les comptes Cloud doivent être validés dans le périmètre client.

Les prochaines briques industrielles sont les collecteurs natifs supplémentaires par OS, la remontée corrélée des événements auditd, les mises à jour authentifiées, les paquets signés/notarisés, les preuves conservées sur un domaine d’administration distinct et les mesures de charge sur un parc. Les correspondances [ISO 27001 / CIS](ISO27001-CIS.md) sont documentées sans revendiquer une certification.
