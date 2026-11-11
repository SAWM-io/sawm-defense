# SAWM Defense en terminal — version 0.2

La CLI et l’application utilisent le même service, les mêmes autorisations et la même base locale. `--state-dir` se place **avant** la commande. Utilisez un chemin privé distinct pour un laboratoire.

## Configurer et démarrer

Sur un serveur sans coffre système disponible, `sawm-defense watch --prompt-key` demande une clé masquée et la conserve uniquement pendant le processus de veille. Ce mode ne suffit pas à un redémarrage autonome sans opérateur : configurez un coffre natif pour le service supervisé. N’inscrivez jamais une vraie clé dans les arguments ou dans le dépôt.

```bash
sawm-defense --state-dir /chemin/prive/profil configure \
  --space MON_ESPACE --entity ent_0123456789abcdef0123456789abcdef \
  --watch-path /srv/dossier-autorise --cloud --upload-events --prompt-key
sawm-defense --state-dir /chemin/prive/profil doctor
sawm-defense --state-dir /chemin/prive/profil check-cloud
sawm-defense --state-dir /chemin/prive/profil watch
```

La clé est demandée sans écho, jamais passée dans la ligne de commande. Remplacez l’entité de l’exemple ; le compte, les scopes, les droits et le crédit Cloud doivent être disponibles. Les chemins sont absolus. Une clé de session ne survit pas à l’invocation : utilisez le coffre système pour un service durable.

Pour une surveillance locale sans partage Cloud :

```bash
sawm-defense configure --no-cloud --no-upload-events \
  --protect-downloads --automatic-scan --notifications
sawm-defense watch --seconds 60
```

Les options booléennes `--protect-downloads`, `--automatic-scan`, `--notifications`, `--autonomous-analysis`, `--auth-journal`, `--auto-block-auth`, `--auto-quarantine`, `--auto-terminate` et `--auto-block-ip` ont une forme inverse `--no-…`. Les options de connexion existantes `--cloud` et `--upload-events` fonctionnent de la même manière. Une option absente conserve son réglage.

L’inspection locale peut fonctionner sans antivirus. Le résultat de `scan` distingue les contrôles structurels (`static_inspection`) et le moteur antivirus (`antivirus`). `no_indicator` n’est pas une certification du fichier ; `suspicious` et `incomplete` restent à examiner. Le fait d’analyser automatiquement ne donne pas la permission de mettre automatiquement en quarantaine.

## Examiner immédiatement

```bash
sawm-defense status
sawm-defense once
sawm-defense inventory
sawm-defense scan /chemin/surveille/fichier.pdf
sawm-defense analyze --event-id IDENTIFIANT_OBSERVATION
sawm-defense chat "Quels faits justifient les alertes et que manque-t-il ?"
sawm-defense report ./rapport.html
sawm-defense report ./rapport.json
```

`once` prend un échantillon local. `analyze` et `chat` utilisent le Cloud selon la configuration et le budget. Le dialogue ne constitue jamais une interface shell. Le rapport contient potentiellement des chemins, adresses et identifiants : protégez son accès.

## Confier une tâche persistante

Démarrez `watch` dans un processus ou service supervisé, puis soumettez des missions depuis un autre terminal utilisant **le même profil** :

```bash
sawm-defense order inventory
sawm-defense order scan --path /chemin/surveille/fichier.pdf
sawm-defense order analyze --event-id IDENTIFIANT_OBSERVATION
sawm-defense order report --path /chemin/prive/rapport.html
sawm-defense orders
sawm-defense notifications
sawm-defense notifications --ack IDENTIFIANT_NOTIFICATION
```

Un identifiant et un état de file ne constituent pas un résultat exécuté. `orders` permet de suivre les états et de lire les reçus. Une mission conserve son origine locale et l’identité de la session. Les missions interrompues dont le résultat nécessite une vérification restent à examiner, sans exécution aveugle en double.

Les types d’ordres sont fermés. Un argument ne peut pas ajouter une nouvelle commande système. Pour une intervention ou un retour arrière explicitement demandé :

```bash
sawm-defense order act --action quarantine --event-id IDENTIFIANT_OBSERVATION --approve
sawm-defense order restore --action-id IDENTIFIANT_ACTION --approve
```

Les variantes immédiates restent disponibles :

```bash
sawm-defense act quarantine IDENTIFIANT_OBSERVATION --approve
sawm-defense restore IDENTIFIANT_ACTION --approve
```

L’approbation ne contourne ni le périmètre, ni l’identité de la cible, ni les exclusions. Une restauration refuse d’écraser un fichier existant ; un processus dont l’identité a changé n’est pas arrêté sur la base de son ancien PID.

## Définir un mandat automatique

Ne lancez ces exemples qu’après avoir adapté les cibles à votre propre politique. Les options accordent des permissions réelles ; une preuve locale vérifiée reste nécessaire au moment de l’action.

```bash
sawm-defense configure --auto-quarantine
sawm-defense configure --auto-terminate --allow-process /chemin/exact/du/programme-autorise
```

Le programme autorisé à être arrêté est un **chemin d’exécutable précis**, pas une permission d’arrêter tous les processus. Le blocage réseau nécessite un exécuteur compatible et les droits système correspondants. Remplacez les valeurs ci-dessous par vos IP exactes :

```bash
sawm-defense configure --auto-block-ip --allow-ip IP_PUBLIQUE_AUTORISEE
sawm-defense configure --protected-ip IP_PUBLIQUE_ADMINISTRATION
```

Pour les échecs SSH, Linux peut fournir une provenance fiable via son journal système :

```bash
sawm-defense configure --auth-journal --autonomous-analysis
sawm-defense configure --auto-block-ip --auto-block-auth --auto-block-seconds 600
```

Cette seconde commande autorise les blocages temporaires des adresses publiques répondant aux conditions d’attribution et de répétition. Les IP protégées restent exclues. Un fichier texte de log peut être observé séparément ; son contenu seul n’autorise pas un blocage automatique :

```bash
sawm-defense configure --auth-log /chemin/autorise/auth.log
```

Le seuil et la fenêtre, visibles dans les réglages et les événements, doivent correspondre à la politique du client. Une série d’échecs indique un comportement à traiter, pas l’identité certaine d’un attaquant.

## Interfaces noyau Linux et démarrage

Consultez d’abord le plan sans modifier le système :

```bash
sawm-defense configure --kernel-audit-path /srv/application
sawm-defense kernel plan
```

L’installation des règles planifiées est une opération explicite, dépendante de l’environnement Linux et des droits de l’administrateur :

```bash
sawm-defense kernel install --approve
```

Les détails et exclusions sont dans [KERNEL.md](KERNEL.md). Le client ne charge pas de pilote noyau universel, n’accorde pas root au modèle et ne couvre pas automatiquement toutes les opérations. Le chemin configuré désigne le répertoire à auditer, pas le fichier de logs. Les traces auditd ne sont pas encore importées dans le tableau de bord ; leur lecture reste celle des outils natifs comme `ausearch`.

Le service utilisateur de démarrage se prépare séparément :

```bash
sawm-defense startup plan
sawm-defense startup install --approve
sawm-defense startup remove --approve
```

Il fonctionne avec les droits de sa session. La supervision avant connexion n’est pas garantie par une tâche utilisateur. Sur Linux serveur, préparez explicitement systemd et le coffre approprié avec l’administrateur.

Si un service surveille déjà le profil, une seconde surveillance est refusée et l’application consulte les observations existantes. Les réglages sont relus et les permissions revérifiées au moment d’agir. La fin d’un appel CLI n’arrête pas un service distinct déjà actif.

Le retrait d’un blocage temporaire est réalisé par le service à l’échéance, puis rattrapé à la reprise si nécessaire. Une règle UFW ou Windows peut donc subsister pendant un arrêt de l’agent ; ce délai n’est pas une expiration garantie par le noyau.
