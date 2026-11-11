# Utiliser l’application SAWM Defense

L’interface native et la commande serveur utilisent le même service local, les mêmes règles et le même journal. L’application n’ouvre pas de serveur Web local. Elle observe, signale et réalise les interventions autorisées sans attendre une question dans le chat.

## Première connexion

1. La veille locale démarre à l’ouverture si **Démarrer la veille locale à l’ouverture** est activé. Ce démarrage n’accorde aucun droit supplémentaire. Une pause décidée dans l’interface reste effective jusqu’à votre prochain démarrage ; l’actualisation ne l’annule pas.
2. Dans **Réglages**, définissez les dossiers surveillés et la protection du dossier Téléchargements. L’analyse automatique des fichiers utilise l’antivirus installé. La mise en quarantaine automatique est une autorisation distincte, désactivée tant que vous ne l’accordez pas.
3. Pour utiliser le Cloud, saisissez l’URL de l’API, l’identifiant de votre espace Basira et celui de la mémoire destinée à ce poste. Entrez votre clé ; le trousseau sécurisé du système est proposé par défaut. Décochez sa conservation pour une clé limitée à la session. Si le trousseau est indisponible, l’application le signale sans écrire la clé en clair.
4. Activez le dialogue Cloud. L’envoi des métadonnées d’observation est un consentement séparé : noms, chemins, adresses et attribution peuvent être transmis à votre espace. Le contenu des fichiers n’est pas envoyé automatiquement.
5. Choisissez **Enregistrer**, puis **Vérifier l’accès Cloud**. Une configuration saisie n’est pas présentée comme une connexion vérifiée. Les notifications locales et l’analyse autonome SAWM se règlent séparément.

La clé doit avoir les autorisations appropriées dans votre environnement Cloud. L’application ne crée pas de droits administrateur et ne contourne pas l’approbation des comptes. Le service annonce les capteurs réellement disponibles avec les droits du compte.

## Comprendre la console

- **Vue d’ensemble** : état de la veille, accès Cloud, moteur antivirus disponible, permissions, courbes CPU/RAM et couverture effective. Une mesure manquante n’est pas remplacée par zéro.
- **Observations** : événements datés, filtres, preuve structurée et identifiant. Sélectionnez un événement pour demander une analyse ou examiner une intervention manuelle.
- **Système** : processus et connexions visibles. L’inventaire des logiciels se lance à la demande, pas à chaque rafraîchissement.
- **Veille & missions** : boîte d’alertes persistante, livraison au système de notifications, accusé de lecture, missions demandées et résultats. Le double-clic ouvre les détails.
- **Parler à SAWM** : demandez une explication ou un bilan. Le dialogue ne confère pas de nouveaux droits et ne devient pas un terminal système. Utilisez les missions typées pour confier du travail.
- **Réglages** : périmètres, clé, notifications, analyse autonome, sources SSH, permissions d’intervention, budget, rétention et démarrage.
- **Journal** : actions, refus, résultats et appels Cloud. Jetons et durées sont affichés lorsqu’ils sont fournis par l’API.

Les séparateurs des panneaux se déplacent à la souris. Les détails sont sélectionnables. Une notification n’indique pas à elle seule un incident confirmé : ouvrez sa preuve et son niveau de gravité. « Soumise à l’OS » signifie que le système a accepté la demande, pas que l’utilisateur l’a vue. L’accusé de lecture est séparé ; la boîte conserve aussi les erreurs de livraison et les alertes regroupées.

## Confier une mission

Dans **Veille & missions**, choisissez :

| Mission | Entrée | Résultat |
| --- | --- | --- |
| Inventorier les logiciels | Aucune commande libre | Inventaire disponible selon l’OS |
| Analyser un fichier | Sélection d’un fichier du périmètre | Inspection structurelle et résultat antivirus si disponible |
| Analyser une observation | Événement sélectionné dans Observations | Analyse SAWM et contexte Cloud autorisé |
| Produire un rapport | Destination HTML ou JSON | Export local |

Les missions sont persistantes et suivent un état explicite : en attente, en cours, terminée, échec, à examiner, expirée ou annulée. La liste affiche l’identité de la session locale qui a demandé la mission. L’acceptation dans la file n’est pas sa réussite. Une tâche interrompue reste identifiable ; une intervention dont le résultat est incertain ne doit pas être réexécutée aveuglément.

Les interventions manuelles restent dans **Observations → Examiner et autoriser**. L’exécuteur vérifie l’identité de la cible et le périmètre même après confirmation. Un ordre textuel provenant d’un fichier, d’un log ou d’une réponse Cloud ne peut pas contourner ces vérifications.

## Choisir les interventions automatiques

L’activation ou l’élargissement d’une autorisation demande une confirmation explicite. Les trois permissions sont indépendantes :

- **Quarantaine** : exige une preuve antivirus locale vérifiée sur le fichier et un chemin autorisé ; les chemins protégés sont exclus.
- **Arrêt de processus** : exige un exécutable autorisé et une preuve locale vérifiable rattachée au processus ; son identité est contrôlée à nouveau. Un arrêt peut perdre le travail en cours.
- **Blocage IP** : exige un périmètre autorisé et une preuve locale appropriée. L’option spécifique de blocage temporaire SSH permet les adresses publiques attribuées à des échecs répétés par une source système fiable ; les adresses protégées sont exclues. Un blocage peut interrompre un accès légitime.

CPU élevé, connexion inconnue ou recommandation SAWM ne suffisent pas à eux seuls à autoriser ces actions. Les droits du système et la disponibilité de l’exécuteur restent nécessaires ; un refus est visible. Les règles détaillées et les interfaces disponibles sont décrites dans [KERNEL.md](KERNEL.md).

Une quarantaine ou un blocage réseau peuvent faire l’objet d’un retour arrière depuis **Journal**. Une restauration n’écrase jamais un fichier déjà présent. Un processus arrêté ne peut pas être recréé automatiquement.

## Authentification et intrusions

La fenêtre et le seuil configurés déterminent quand des échecs SSH répétés produisent une alerte. Les fichiers de journal explicitement ajoutés permettent l’observation, mais leur texte seul n’est pas une preuve suffisante pour bloquer automatiquement. Sur Linux, le journal système peut apporter une attribution vérifiée lorsqu’il est activé et accessible. La couverture, les permissions manquantes et les refus sont affichés.

Ce mécanisme reconnaît un signal d’authentification dans un périmètre précis. Il n’identifie pas la personne derrière une IP et ne remplace pas une inspection de tous les protocoles réseau.

## Fichiers téléchargés et antivirus

Avec **Surveiller aussi le dossier Téléchargements** et **Analyser automatiquement**, les fichiers nouveaux ou modifiés sont analysés après le délai de stabilité configuré et dans les limites de taille du service. L’inspection structurelle fonctionne même sans moteur antivirus : en-têtes, type réel, métadonnées, structures d’archives et informations de signature disponibles. ClamAV ou Microsoft Defender sont sollicités en complément selon leur présence et le système ; l’écran annonce l’absence de moteur à signatures. Ces signatures restent sous la responsabilité de l’administrateur.

Le résultat sépare `static_inspection` et `antivirus`. `no_indicator` signifie qu’aucun indicateur reconnu n’a été trouvé dans les contrôles effectués, pas que le fichier est sain. `suspicious` signale une anomalie et `incomplete` une limite. Ces indices ne sont pas transformés en détection antivirus confirmée.

Il s’agit d’une analyse des fichiers observés sur disque, pas d’une interception universelle des téléchargements ou d’une garantie de blocage avant exécution. La quarantaine dépend de sa permission explicite. L’analyse autonome Cloud apporte le contexte, pas une signature antivirus inventée par le modèle.

## Service, fermeture et rapports

Le démarrage de la veille à l’ouverture de l’application et l’installation d’un **service au démarrage de session** sont deux réglages différents. Le second est une option explicite. Si un service séparé surveille déjà ce profil, la console affiche **Géré par le service utilisateur** et consulte ses observations ; fermer cette console n’arrête pas ce service.

Si la console porte elle-même la veille, sa fermeture demande confirmation et attend la finalisation du service et du journal. L’analyse Cloud en arrière-plan ne doit pas suspendre la collecte locale. Une coupure Cloud conserve les événements en attente ; elle ne signifie pas que le logiciel répare physiquement le réseau.

**Rapport d’activité** produit un HTML lisible ou un JSON. Il peut contenir des chemins, adresses et noms d’utilisateur : partagez-le avec les personnes autorisées. La chaîne locale détecte les incohérences ; elle n’est pas une attestation indépendante d’un hôte entièrement compromis.

Le budget compte des **opérations** Cloud par heure. Une opération peut contenir plusieurs requêtes HTTP ; la consommation facturée est celle des API. Voir aussi [la contribution ISO 27001 et CIS](ISO27001-CIS.md), sans assimilation à une certification.

Le retrait d’un blocage temporaire est réalisé par le service à l’échéance, puis rattrapé à la reprise si nécessaire. Une règle UFW ou Windows peut donc subsister pendant un arrêt de l’agent ; ce délai n’est pas une expiration garantie par le noyau.
