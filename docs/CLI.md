# Même agent, sans interface graphique

`--state-dir` se place avant la commande et permet d’isoler plusieurs profils. Sans cet argument, le profil de l’application est utilisé.

```bash
sawm-defense --state-dir /chemin/prive/profil configure \
  --space MON_ESPACE --entity ent_0123456789abcdef0123456789abcdef \
  --watch-path /srv/dossier-autorise --cloud --upload-events --prompt-key
sawm-defense --state-dir /chemin/prive/profil doctor
sawm-defense --state-dir /chemin/prive/profil check-cloud
sawm-defense --state-dir /chemin/prive/profil watch
```

La clé est demandée sans écho, jamais dans la ligne de commande. L’entité donnée ici est un exemple à remplacer. Le compte Cloud doit être activé, les scopes et crédits disponibles. Les chemins du périmètre sont absolus.

```bash
sawm-defense once
sawm-defense inventory
sawm-defense scan /chemin/surveille/fichier.pdf
sawm-defense analyze --event-id IDENTIFIANT_OBSERVATION
sawm-defense chat "Quels faits justifient les alertes et que manque-t-il ?"
sawm-defense act quarantine IDENTIFIANT_OBSERVATION --approve
sawm-defense restore IDENTIFIANT_ACTION --approve
sawm-defense report ./rapport.html
sawm-defense report ./rapport.json
sawm-defense startup plan
sawm-defense startup install --approve
sawm-defense startup remove --approve
```

Une confirmation ne permet pas de sortir du périmètre, d’écraser un fichier à la restauration ou de tuer un processus dont l’identité a changé. La preuve d’une intervention doit être récente. Le résultat contient toujours un statut : refus, erreur ou exécution constatée.

Le service tourne dans la session utilisateur, avec ses droits. Il ne garantit pas la supervision avant connexion de l’utilisateur. Sur Linux serveur, configurer explicitement le gestionnaire systemd et le coffre de secrets appropriés ; aucun mot de passe root n’est demandé ou conservé.

Si le service tourne déjà, l’application affiche sa dernière mesure et son journal. Une seconde surveillance du même profil est refusée. Les modifications des réglages sont relues par le service ; les autorisations sont contrôlées à nouveau au moment d’une action.
