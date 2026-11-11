# Architecture du client de défense

Le même `AgentService` sert la CLI et l’application Tkinter. La surveillance et les appels Cloud ont des workers séparés : une requête lente n’arrête pas l’échantillonnage local. Les deux exécutables de distribution ont le même code métier.

- `platforms.py` : observations bornées, sans modification ni pilote noyau.
- `antivirus.py` : intégration de moteurs installés, pas d’analyse LLM présentée comme antivirus.
- `storage.py` : journal SQLite append-only, files idempotentes, compteur d’opérations, ancre conservée lors de la rétention.
- `cloud.py` : SDK public, ingestion Basira, TSST, classement ODVL sans ajout/retrait de preuve, tour SAWM terminé et JSON validé.
- `policy.py` : autorité locale, fraîcheur de preuve, abstention en cas d’incertitude.
- `actions.py` : petite liste d’interventions, contrôle des cibles, reçus et retour arrière.
- `secrets.py` : clés dans un coffre natif et liées à la destination, pas de fichier `.env` distribué.
- `autorun.py` : service utilisateur supervisé, installation explicite et refus de remplacer un service tiers.

## Qui agit

SAWM produit une proposition et une justification synthétique. L’application ne demande ni n’expose un raisonnement interne privé. Les propositions, observations, décisions locales et effets constatés sont distingués dans le journal.

L’autonomie v0.1 couvre l’observation, l’analyse Cloud des signaux pertinents lorsque le partage est activé, et la quarantaine d’une détection antivirus locale vérifiée lorsque l’utilisateur l’autorise. Un signal CPU, une IP inhabituelle ou un jugement du modèle ne suffit pas pour tuer un processus.

Les arrêts de processus contrôlent utilisateur, PID, heure de création, chemin et empreinte. Les blocages IP sont limités aux adresses publiques explicitement autorisées et ne désactivent jamais toute l’interface réseau. Les destinations Cloud et résolveurs connus sont protégés. L’effet d’un blocage réseau reste à vérifier sur le système cible.

## Limites avant déploiement industriel

Le client fonctionne avec les droits de l’utilisateur. Il ne couvre pas tous les événements noyau ni une compromission de l’administrateur. Les prochaines briques possibles sont des capteurs système signés et dédiés par OS, une supervision institutionnelle extérieure, la signature/notarisation des paquets, un mécanisme de mise à jour authentifiée, une mesure de charge sur un parc, et une campagne native Windows/Linux.

Les résultats actuels n’établissent aucune certification ISO, antivirus ou EDR. Les moteurs Cloud restent distincts des collecteurs installés sur le poste. Les licences, contrats de service et exigences de protection des données de chaque déploiement doivent correspondre à son périmètre réel.
