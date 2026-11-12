# Utiliser l’application SAWM Defense

L’interface native et la commande serveur utilisent le même service local, les mêmes règles et le même journal. L’application n’ouvre pas de serveur Web local. Elle observe, signale et réalise les interventions autorisées sans attendre une question dans le chat.

Ce guide décrit la **console SOC 0.3**. Vérifiez la version installée ; les paquets 0.2.1 n’incluent pas encore ces nouveaux écrans.

## Première connexion

1. La veille locale démarre à l’ouverture si **Démarrer la veille locale à l’ouverture** est activé. Ce démarrage n’accorde aucun droit supplémentaire. Une pause décidée dans l’interface reste effective jusqu’à votre prochain démarrage ; l’actualisation ne l’annule pas.
2. Dans **Réglages**, définissez les dossiers surveillés et la protection du dossier Téléchargements. L’analyse automatique des fichiers utilise l’antivirus installé. La mise en quarantaine automatique est une autorisation distincte, désactivée tant que vous ne l’accordez pas.
3. Pour utiliser le Cloud, saisissez l’URL de l’API, l’identifiant de votre espace Basira et celui de la mémoire destinée à ce poste. Entrez votre clé ; le trousseau sécurisé du système est proposé par défaut. Décochez sa conservation pour une clé limitée à la session. Si le trousseau est indisponible, l’application le signale sans écrire la clé en clair.
4. Activez le dialogue Cloud. L’envoi des métadonnées d’observation est un consentement séparé : noms, chemins, adresses et attribution peuvent être transmis à votre espace. Le contenu des fichiers n’est pas envoyé automatiquement.
5. Choisissez **Enregistrer**, puis **Vérifier l’accès Cloud**. Une configuration saisie n’est pas présentée comme une connexion vérifiée. Les notifications locales et l’analyse autonome SAWM se règlent séparément.

La clé doit avoir les autorisations appropriées dans votre environnement Cloud. L’application ne crée pas de droits administrateur et ne contourne pas l’approbation des comptes. Le service annonce les capteurs réellement disponibles avec les droits du compte.

## Comprendre la console

- **Console SOC** : état de la veille, signaux critiques ou à examiner, cadence SAWM, dernière et prochaine revue, file d’analyse, sources et budget API réel. Les courbes CPU/RAM reposent sur les échantillons du service. Le bouton **Capteurs & limites** ouvre la couverture détaillée sans encombrer les priorités. Une mesure absente n’est pas remplacée par zéro.
- **Observations** : événements datés, filtres, preuve structurée et identifiant. Sélectionnez un événement pour demander une analyse ou examiner une intervention manuelle.
- **Système** : processus et connexions visibles. L’inventaire des logiciels se lance à la demande, pas à chaque rafraîchissement.
- **Réseau & accès** : référence réseau, événements de connexion, changements de droits des chemins choisis et journaux LDAP. Filtrez par famille puis sélectionnez une ligne pour lire la provenance et l’attribution. Ces données restent en lecture seule ; aucun compte LDAP n’est modifié.
- **Veille & missions** : boîte d’alertes persistante, livraison au système de notifications, accusé de lecture, missions demandées et résultats. Le double-clic ouvre les détails.
- **SAWM** : demandez une explication ou un bilan. Le dialogue ne confère pas de nouveaux droits et ne devient pas un terminal système. Utilisez les missions typées pour confier du travail.
- **Réglages** : périmètres, clé, notifications, analyse autonome, sources SSH, permissions d’intervention, budget, rétention et démarrage.
- **Journal** : actions, refus, résultats et appels Cloud. Jetons et durées sont affichés lorsqu’ils sont fournis par l’API.

Les séparateurs des panneaux se déplacent à la souris. Les détails sont sélectionnables. Une notification n’indique pas à elle seule un incident confirmé : ouvrez sa preuve et son niveau de gravité. « Soumise à l’OS » signifie que le système a accepté la demande, pas que l’utilisateur l’a vue. L’accusé de lecture est séparé ; la boîte conserve aussi les erreurs de livraison et les alertes regroupées.

## Cadence, préréglages et coût

Dans **Réglages → Cadence d’analyse & plafond Cloud**, choisissez **Équilibré** (30 secondes, 1 200 requêtes API/h) ou **Serveur critique** (10 secondes, 3 600 requêtes API/h), puis cliquez **Préparer ces réglages**. Les nombres changent à l’écran, mais rien n’est encore enregistré. Le Cloud, le partage et le mandat restent inchangés. **Enregistrer** présente une confirmation pour les nouvelles valeurs et les augmentations de coût ou de droits.

La cadence locale mesure la machine ; la cadence SAWM décide quand une revue Cloud peut commencer. Elles sont distinctes. Avec le rythme adaptatif, une file critique peut être revue à 10 secondes ; une file vide ralentit le rythme de base jusqu’à quatre fois, sans envoyer une analyse inutile. **Effectuer une revue périodique même sans alerte nouvelle** demande explicitement un bilan périodique et consomme des appels Cloud. Désactivez cette option pour réserver les analyses aux signaux à examiner.

Le compteur affiche les **requêtes API réelles** utilisées/restantes, pas un nombre d’analyses ni des euros. Une analyse utilise plusieurs requêtes ; les tentatives échouées comptent aussi. **0 = appels suspendus**, jamais illimités. Le Cloud est désactivé dans un nouveau profil ; son plafond initial de 1 200 requêtes/h n’autorise pas son activation. Les anciens plafonds sont conservés.

Dans la console, **Dernière revue** est une tentative ; **Dernière réussite** est un retour effectivement reçu. Une reprise différée ou un budget épuisé reste visible. La date de prochaine revue est une échéance cible, pas une garantie de délai. Double-cliquez une observation prioritaire pour ouvrir sa preuve ; ouvrez une ligne de la file pour consulter ce qui attend l’analyse. Cette file ne prouve pas qu’un incident est résolu.

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

## Réseau, droits et LDAP

La corrélation réseau travaille sur les sockets accessibles au compte, sans balayage du réseau ni déchiffrement de trafic. Une référence conserve les associations vues entre programme, utilisateur, destination et service ; elle n’est pas une liste de destinations certifiées sûres. Les séquences de ports/destinations et les changements de référence restent des signaux à examiner.

Trois listes ont des rôles différents : **IP autorisées au blocage** désigne les cibles sur lesquelles une intervention est permise ; **IP interdites** définit la politique réseau à surveiller ; **IP protégées** exclut des adresses de toute intervention. Une permission générale de blocage ne transforme pas toutes les autres connexions en infractions. Le blocage automatique d’une destination interdite exige son option distincte, une preuve récente attribuée, les permissions et un exécuteur disponible.

Pour les accès, configurez les chemins exacts et les journaux OpenLDAP `slapd` accessibles. L’observation de permissions/propriétaires ne parcourt pas automatiquement toute une arborescence et n’identifie pas l’auteur de chaque changement. Sous Windows, les bits de fichier ne représentent pas une analyse complète des ACL. Les journaux LDAP importés sont des textes non authentifiés : échecs répétés et changements d’attributs produisent des alertes, sans modification d’identité ni révocation autonome.

## Fichiers téléchargés et antivirus

Avec **Surveiller aussi le dossier Téléchargements** et **Analyser automatiquement**, les fichiers nouveaux ou modifiés sont analysés après le délai de stabilité configuré et dans les limites de taille du service. L’inspection structurelle fonctionne même sans moteur antivirus : en-têtes, type réel, métadonnées, structures d’archives et informations de signature disponibles. ClamAV ou Microsoft Defender sont sollicités en complément selon leur présence et le système ; l’écran annonce l’absence de moteur à signatures. Ces signatures restent sous la responsabilité de l’administrateur.

Le résultat sépare `static_inspection` et `antivirus`. `no_indicator` signifie qu’aucun indicateur reconnu n’a été trouvé dans les contrôles effectués, pas que le fichier est sain. `suspicious` signale une anomalie et `incomplete` une limite. Ces indices ne sont pas transformés en détection antivirus confirmée.

Il s’agit d’une analyse des fichiers observés sur disque, pas d’une interception universelle des téléchargements ou d’une garantie de blocage avant exécution. La quarantaine dépend de sa permission explicite. L’analyse autonome Cloud apporte le contexte, pas une signature antivirus inventée par le modèle.

## Service, fermeture et rapports

Le démarrage de la veille à l’ouverture de l’application et l’installation d’un **service au démarrage de session** sont deux réglages différents. Le second est une option explicite. Si un service séparé surveille déjà ce profil, la console affiche **Géré par le service utilisateur** et consulte ses observations ; fermer cette console n’arrête pas ce service.

Si la console porte elle-même la veille, sa fermeture demande confirmation et attend la finalisation du service et du journal. L’analyse Cloud en arrière-plan ne doit pas suspendre la collecte locale. Une coupure Cloud conserve les événements en attente ; elle ne signifie pas que le logiciel répare physiquement le réseau.

**Rapport d’activité** produit un HTML lisible ou un JSON. Il peut contenir des chemins, adresses et noms d’utilisateur : partagez-le avec les personnes autorisées. La chaîne locale détecte les incohérences ; elle n’est pas une attestation indépendante d’un hôte entièrement compromis.

Le budget compte les **requêtes API réelles** par heure. La consommation facturée dépend des API et des jetons ; le compteur de requêtes n’est pas un compteur de dépenses en euros. Voir aussi [la contribution ISO 27001 et CIS](ISO27001-CIS.md), sans assimilation à une certification.

Le retrait d’un blocage temporaire est réalisé par le service à l’échéance, puis rattrapé à la reprise si nécessaire. Une règle UFW ou Windows peut donc subsister pendant un arrêt de l’agent ; ce délai n’est pas une expiration garantie par le noyau.
