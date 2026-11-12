# SAWM Defense — contribution à un SMSI ISO 27001 et base technique CIS

Références vérifiées le **12 novembre 2026**. Périmètre : l’application de poste et le service local de ce dépôt, avec accès facultatif aux API SAWM / Basira Cloud.

La version publiée consultée est **ISO/IEC 27001:2022**, complétée par **Amd 1:2024**. Cette norme définit les exigences d’un système de management de la sécurité de l’information (SMSI), avec des responsabilités organisationnelles et des mesures techniques. L’amendement porte sur la prise en compte du changement climatique dans le contexte du système de management ; ce n’est pas une nouvelle fonction antivirus. [ISO 27001](https://www.iso.org/standard/27001), [amendement officiel](https://www.iso.org/standard/88435.html).

La référence technique utilisée ici est **CIS Controls v8.1**, présentée sur le site officiel de CIS. [Présentation officielle](https://www.cisecurity.org/controls/v8-1).

**SAWM Defense apporte des fonctions et des preuves à cette démarche. L’application n’est ni une certification ISO, ni un audit complet des contrôles CIS.** Aucune couverture en pourcentage n’est déduite de la présence d’une fonction. L’organisation reste responsable de son analyse de risques, de son périmètre, de sa déclaration d’applicabilité, de ses procédures et de leur validation.

## Correspondances techniques vérifiables

Les correspondances ci-dessous sont une analyse du dépôt, pas une attestation d’un organisme de certification. Les catégories ISO décrivent des thèmes de contrôle : le texte normatif complet et la déclaration d’applicabilité du client restent la référence pour un audit formel.

| Thème ISO / référence CIS | Contribution de l’application | Preuve consultable | Ce qui reste à assurer dans l’organisation |
| --- | --- | --- | --- |
| Actifs et logiciels — [CIS 2](https://www.cisecurity.org/controls/inventory-and-control-of-software-assets) | Inventaire des logiciels, liste des processus visibles et de leurs exécutables. | Mission `inventory`, résultat horodaté et vue Système. | Inventaire exhaustif du parc, politique d’installation, licences, vulnérabilités et correctifs. Un inventaire ne lit pas le code source de tous les logiciels. |
| Droits et privilèges — [CIS 6](https://www.cisecurity.org/controls/access-control-management) | Autorisations explicites d’action, chemins/IP autorisés, chemins/IP protégés, contrôle local au moment d’agir. Clé Cloud dans le trousseau, jamais conférée par une réponse de SAWM. En 0.3, observation des métadonnées de droits des chemins choisis et des journaux OpenLDAP en lecture seule. | Réglages, refus de politique, reçu d’action, identité de la session demandant une mission. | Gestion des identités de l’entreprise, MFA, revue périodique des droits, révocation et séparation des administrateurs. |
| Journalisation et surveillance — [CIS 8](https://www.cisecurity.org/controls/audit-log-management) | Événements, notifications, missions et reçus conservés localement ; journal chaîné ; synchronisation Cloud lorsque autorisée. | Onglets Observations, Veille & missions et Journal ; export HTML/JSON ; vérification de chaîne. | Centralisation indépendante, synchronisation horaire, sauvegarde et rétention réglementaire. Un administrateur hostile peut réécrire un journal entièrement local. |
| Protection contre les logiciels malveillants — [CIS 10](https://www.cisecurity.org/controls/malware-defenses) | Inspection structurelle des fichiers stables ; antivirus local lorsqu’il est disponible ; quarantaine et arrêt ciblé soumis à preuve et périmètre. | Identité du moteur, résultat de scan, hash, reçu d’intervention et erreur explicite si moteur absent. | Installation et mise à jour des signatures, couverture de tous les fichiers, prévention avant exécution et validation avec des produits de sécurité adaptés. |
| Surveillance réseau — [CIS 13](https://www.cisecurity.org/controls/network-monitoring-and-defense) | Connexions visibles ; référence par programme/utilisateur/destination/service ; indices de ports/destinations multiples ; politique d’IP interdites explicite. Corrélation SSH et blocage temporaire autorisé des sources attribuées par journal système fiable. | Source et confiance de l’observation, seuil/fenêtre, décision, règle appliquée et retour arrière. | Inspection réseau complète, IDS/IPS, segmentation, couverture des protocoles et systèmes non pris en charge. Une IP n’identifie pas une personne. |
| Gestion des incidents — [CIS 17](https://www.cisecurity.org/controls/incident-response-management) | Notification, file d’analyse priorisée, cadence adaptative et reprise après panne, décision contrôlée, mission persistante, reçu du résultat et revue humaine. | Alerte → événement → analyse → reçu → résultat ; état des tâches interrompues. | Responsable d’incident, escalade, exercices, communication, délais de réponse et validation des critères de clôture. |

Les liens CIS renvoient aux objectifs des contrôles ; les colonnes « contribution » et « preuve » décrivent nos fonctions locales. Elles ne prétendent pas satisfaire l’ensemble des mesures de chaque contrôle.

## Autonomie et défense en profondeur

1. **Observer localement.** Les capteurs continuent selon leurs droits, même si le Cloud ne répond pas. La collecte annonce ses sources absentes ou refusées. Le dossier Téléchargements et les chemins explicitement configurés définissent la couverture fichier.
2. **Conserver et signaler.** L’alerte entre dans une boîte locale persistante. Le service tente une notification native si l’option est activée. « Soumise à l’OS » n’est pas une preuve que l’utilisateur l’a vue ; l’accusé de lecture est séparé.
3. **Analyser dans un budget.** Une alerte peut être analysée par SAWM en arrière-plan avec le contexte autorisé. TSST et ODVL participent au rappel via les API Cloud ; l’application ne contient pas leur code privé. Aucun appel Cloud n’est indispensable à l’exécution d’une protection locale déjà autorisée et vérifiable.
4. **Vérifier l’autorité.** Le texte d’un fichier, d’un journal ou d’une réponse Cloud reste une donnée. Il ne peut pas transformer une mission en commande shell ni élargir le périmètre d’action. Les réglages et l’exécuteur local déterminent les droits.
5. **Agir sur une cible attribuée.** Le fichier, le processus ou l’adresse sont revérifiés. Les anomalies isolées ne donnent pas de permission de détruire. Le blocage autonome SSH exige une provenance système vérifiée ; un fichier texte importé ne suffit pas.
6. **Évaluer le résultat.** Le reçu distingue refus, erreur et action exécutée. Un processus arrêté n’est pas un service restauré ; une règle réseau créée n’atteste pas à elle seule l’arrêt d’une campagne d’attaque. Les cas nécessitant une revue restent visibles.

Voir [le guide d’interface](INTERFACE.md) et [les interfaces système et noyau](KERNEL.md). Les droits administrateur ne sont pas acquis automatiquement. L’agent s’exécute en espace utilisateur et sollicite les interfaces du système selon les droits accordés ; il n’est pas installé dans le code du noyau.

## Console SOC 0.3 : ce que les nouveaux indicateurs attestent

Le tableau de bord expose les signaux reçus, la file d’analyse, la dernière tentative, le dernier retour réussi, les échéances et les requêtes API réellement comptabilisées. Ces indicateurs rendent les interruptions et limites de coût vérifiables ; ils ne certifient pas que l’ensemble du réseau est couvert ou qu’un incident est résolu.

Les préréglages 30 ou 10 secondes ne sont pas des engagements de temps de réponse. Les droits d’intervention restent indépendants du rythme d’analyse et du budget. Une revue sans nouvelle alerte exige une option explicite ; un plafond nul interdit les appels. Les journaux LDAP importés ne fournissent pas l’assurance d’un connecteur IAM authentifié et ne déclenchent aucun changement d’annuaire. Les écarts de permissions observés ne suffisent pas à identifier leur auteur.

Pour une contribution mesurable aux contrôles d’accès et de surveillance réseau, conserver la source, sa limite d’attribution, l’avant/après constaté, l’IP interdite par la politique et le reçu d’une éventuelle intervention. L’organisation doit encore valider ses sources et ses procédures de réponse. [CIS 6 — gestion des accès](https://www.cisecurity.org/controls/access-control-management), [CIS 13 — surveillance et défense réseau](https://www.cisecurity.org/controls/network-monitoring-and-defense).

## Dossier de preuve pour un pilote

Pour chaque hôte et version, conserver : configuration et périmètre approuvés, résultats de disponibilité des capteurs, version et mise à jour antivirus, règles autorisées, événements datés, appel Cloud et consommation lorsque fournis, action et identité du demandeur, résultat constaté et cas non couverts. Exclure les clés et restreindre la diffusion des adresses, chemins et identifiants.

Exercer au minimum : alerte locale sans Cloud ; notification désactivée ou indisponible ; moteur antivirus absent ; fichier innocent ; preuve antivirus de contrôle ; refus hors périmètre ; absence d’élévation silencieuse ; échecs SSH sous le seuil et au-dessus ; faux journal non fiable ; IP protégée ; retour arrière ; reprise d’une mission après interruption. Exécuter les mesures natives sur chaque OS ciblé, puis consigner la version réellement éprouvée. Les tests isolés ne remplacent pas les validations Windows, Linux et macOS sur machine.

## Ce que l’application ne certifie pas

La couverture de toutes les intrusions, l’inspection de tout trafic, la résistance à un noyau compromis, le blocage universel des malwares avant leur exécution et la conformité d’une organisation entière ne sont pas démontrés par ce dépôt. La procédure de management ISO (personnes, risques, fournisseurs, continuité, audits internes et amélioration) reste à mettre en œuvre et à évaluer séparément.
