# Validation — SAWM Defense 0.2.1

## Livraison multiplateforme 0.2.1

Le 12 novembre 2026, la suite locale macOS a réussi **329 tests**, dont les contrôles des preuves de livraison et la reprise d’une installation source interrompue. Les comptes natifs exacts et les éventuels tests exclus sont conservés dans les journaux GitHub Actions de chaque plateforme.

Avant de créer une archive, le pipeline vérifie le CLI réellement compilé : version annoncée, SHA256 du binaire, effets des opérations de fichiers, intégrité du journal, contenu des exports, notification persistante et mission exécutée par le service. Une preuve absente, incomplète, négative ou portant sur un autre binaire bloque l’archivage. Le rapport `PACKAGED-VALIDATION.json` porte le schéma 2.

Une seconde sonde ouvre le binaire graphique avec un profil temporaire hors ligne et vérifie une fenêtre visible appartenant à son PID. Les preuves `docs/packaged-gui-*.json` décrivent la méthode native et la terminaison du processus de test. Ce contrôle d’ouverture ne simule pas les clics métier, ne vérifie pas un compte Cloud réel et ne prouve pas une intervention sur le pare-feu. Il s’exécute sous Xvfb pour Linux, via Win32 pour Windows et CoreGraphics pour macOS.

Les fichiers historiques ci-dessous conservent leur version d’origine ; ils ne servent pas de preuve pour un nouveau paquet. La version 0.2.1 continue les observations de fichiers et du réseau si l’énumération des processus est refusée, et annonce explicitement la couverture incomplète.

État documentaire : **11 novembre 2026**. Ce fichier distingue les contrôles du code, les opérations réellement exécutées et les validations natives restant à compléter. Il ne transforme pas la réussite d’un test avec fournisseur simulé en réussite d’un appel Cloud réel.

## Périmètre de la campagne locale

L’environnement de développement est macOS Apple Silicon, Python 3.12.14 et Tk 9.0.4. La suite se lance avec :

```bash
python -m pytest -q
```

La campagne locale 0.2 a réussi **199 tests**. Bandit ne relève aucune alerte de sévérité moyenne ou élevée. Le [contrôle du paquet Mac 0.2](packaged-macos-validation-0.2.json) vérifie le CLI réellement construit : modification/suppression de fichier, quarantaine manuelle et restauration, détection structurelle automatique d’un script de test déguisé en PDF, alerte persistante et exécution d’une mission de rapport par le service. Le moteur antivirus était absent et le Cloud désactivé ; le fichier suspect n’a pas été supprimé sur la seule base de l’heuristique.

L’interface 0.2 a également été ouverte et observée : veille active, graphe des ressources et onglet Veille & missions. Le signal d’absence d’antivirus est regroupé par changement d’état pour éviter une alerte identique à chaque fichier. Les fonctions privilégiées ne sont pas déduites de cette vérification visuelle.

Sous Windows, la confidentialité du dossier d’état dépend des ACL du profil utilisateur ; les bits de mode POSIX ne mesurent pas ces droits. Les clés API restent dans le coffre système, jamais dans le fichier de configuration. Un dossier d’état partagé doit être protégé par des ACL appropriées.

Le total exact doit être lu dans la sortie de la campagne correspondant au commit livré. Il n’est pas repris d’une version précédente. Les contrôles GUI utilisent de vrais widgets Tk dans un sous-processus isolé ; les assertions de service sont injectées pour ne pas modifier les permissions du poste.

| Partie | Nature des preuves | Interprétation |
| --- | --- | --- |
| Fichiers et journal | Fichiers temporaires réels, création/modification/suppression, empreintes, rétention et chaîne locale | Valide ces chemins logiciels dans le périmètre temporaire |
| Quarantaine et restauration | Opérations réelles sur fichiers inoffensifs ; détection contrôlée pour les scénarios | Ne constitue pas une campagne sur malwares réels |
| Processus | Sous-processus de test autorisé et vérification d’identité, refus hors périmètre | Ne prouve pas la sûreté de l’arrêt de tous les services d’entreprise |
| Cloud / SDK public | `httpx.MockTransport`, contrat des requêtes, échecs, budget, TSST/ODVL et réponses SAWM contrôlées | Aucun compte client ni clé réelle dans cette campagne locale |
| Interface native | Widgets réels, appels hors du thread graphique, missions typées, accusé de lecture, refus de permission annulée et démarrage unique | Ne prouve pas la livraison d’un toast sur toutes les versions des OS |
| Commandes OS | Arguments et contrôles examinés sans appliquer les règles au pare-feu du poste | UFW, Windows Firewall, services et règles d’audit nécessitent une campagne native |
| Analyse de fichiers | Fichiers de contrôle, limites, en-têtes/structures et résultats distincts des signatures antivirus | Aucun indicateur reconnu n’équivaut pas à absence de malware |

Les tests spécifiques de la version 0.2 portent sur les notifications et leur persistance, les missions et leur reprise, l’analyse autonome, l’origine des journaux SSH, les permissions et les téléchargements. Chaque compte rendu doit préciser ce qui a réellement été exécuté au commit évalué, et conserver les échecs ou fonctions non exercées.

## Autonomie : critères de validation

- Une observation arrive sans dialogue préalable ; une alerte est enregistrée et sa notification est tentée selon les réglages.
- Notification soumise au système, notification visible et notification lue sont trois faits distincts.
- Une analyse Cloud lente ne bloque pas les échantillons locaux. Une panne, un budget épuisé ou une réponse invalide restent des états explicites.
- Une mission persiste avec son identifiant, sa demande, son acteur et son résultat. Une action interrompue au résultat incertain ne doit pas être relancée aveuglément.
- Une permission révoquée ou une cible devenue différente entraîne un refus au moment d’agir.
- Un texte hostile dans un fichier, un log ou un rappel ne devient pas une instruction à exécuter.
- Une preuve antivirus valide est distincte d’un indice de fichier suspect. Un pic CPU seul n’autorise pas un arrêt.
- Des échecs SSH sous le seuil, une IP protégée et un log non fiable ne doivent pas conduire au même traitement qu’une source système attribuée dépassant le seuil.
- Les interventions refusées et les échecs apparaissent avec leur raison, pas comme des réussites.
- La pause utilisateur reste effective malgré les rafraîchissements de l’interface.

## Reproduire sans compte Cloud réel

Utilisez un profil jetable et des fichiers de contrôle inoffensifs. N’accordez pas de nouvelle permission d’action pour faire un simple contrôle de disponibilité :

```bash
python -m pytest tests/test_gui.py tests/test_notifications.py tests/test_orders.py -q
python -m sawm_defense --state-dir /chemin/jetable doctor
python -m sawm_defense --state-dir /chemin/jetable kernel plan
python -m sawm_defense --state-dir /chemin/jetable watch --seconds 10
python -m sawm_defense --state-dir /chemin/jetable status
python -m sawm_defense --state-dir /chemin/jetable notifications
python -m sawm_defense --state-dir /chemin/jetable orders
```

Les commandes `watch` et `doctor` lisent ce que le profil autorise réellement, notamment Téléchargements si l’option est activée. Pour un laboratoire entièrement isolé, désactivez cette option et définissez uniquement un dossier de test. `kernel plan` est informatif ; `kernel install --approve` modifie le système et appartient à une campagne Linux autorisée.

## Paquets natifs et preuves antérieures

La campagne **0.1** a ouvert visuellement l’application macOS construite avec PyInstaller : configuration, démarrage/arrêt, mesures et graphe CPU/RAM. Le CLI du paquet a réellement détecté des changements de fichiers temporaires, mis un fichier inoffensif en quarantaine, restauré ce fichier et exporté un rapport avec journal valide.

L’artefact [packaged-macos-validation.json](packaged-macos-validation.json) appartient à cette campagne antérieure. Il **ne valide pas automatiquement les nouvelles fonctions 0.2** ni un paquet non reconstruit. La construction 0.2 doit être lancée avec `python packaging/build.py`, puis son CLI et son interface vérifiés à nouveau.

L’analyse Bandit antérieure ne remplace pas l’analyse du commit courant. Les commandes système restent des points de revue, y compris lorsqu’elles sont légitimes et bornées.

## À valider sur les environnements clients

1. **Cloud réel** : espace dédié, clé minimale, consentement, TSST/ODVL, dépôt, rappel, analyse SAWM, budget, panne et reprise ; aucun résultat de transport simulé ne remplace cet essai.
2. **Linux natif** : source SSH réellement attribuée, règles d’audit, UFW dans son état initial connu, blocage temporaire et retrait, accès d’administration protégé, notifications selon session.
3. **Windows natif** : intégration Defender et résultats ambigus, Windows Firewall, notifications, tâche planifiée et refus des permissions absentes.
4. **macOS natif** : disponibilités réseau selon droits, notifications système, ClamAV si installé, inspection des fichiers, profil et démarrage supervisé.
5. **Exploitation** : volume d’événements, latence, stockage pendant panne prolongée, consommation Cloud, faux positifs, restauration et service légitime préservé.

Aucun résultat local ne démontre une détection universelle des malwares, une résistance à un administrateur ou noyau hostile, l’interception de chaque téléchargement avant son exécution ou la certification ISO d’une organisation. Le dossier [ISO 27001 / CIS](ISO27001-CIS.md) décrit les contributions techniques et les preuves attendues.
