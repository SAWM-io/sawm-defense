# Linux : sources vérifiables et audit du noyau

SAWM reste un programme en espace utilisateur. Les capteurs lisent les observations du système ; la politique locale autorise les réponses ; les outils natifs appliquent les opérations prévues. Un texte du Cloud ne devient jamais une commande shell, un module Linux ou un programme eBPF.

## Détection autonome des échecs SSH

Sur Linux, activer `auth_journal_enabled` et donner au compte du service le droit de lire le journal système. La première lecture couvre au maximum la fenêtre configurée, puis le curseur journald est conservé sur disque. Le seuil par défaut est de **5 échecs SSH distincts depuis une même IP en 300 secondes**.

Le capteur vérifie ensemble :

- le lecteur natif `journalctl`, appartenant à root dans une arborescence non modifiable par les autres comptes ;
- les métadonnées journald `_UID=0`, `_COMM=sshd` ou `sshd-session`, `_EXE` correspondant à un exécutable SSH système protégé ;
- `_TRANSPORT=syslog`, le format exact du message d'échec SSH, son horodatage et son curseur distinct ;
- le nombre d'événements dans la fenêtre, sans compter deux fois un même curseur.

L'événement produit est `auth_bruteforce`. Une source vérifiée porte `verification_origin=local_journald` et `verified_local=true`. Ce sont des **preuves d'échecs d'authentification**, pas une identification de la personne ni une preuve de malware. Une IP peut représenter plusieurs utilisateurs ou un relais. Ni pays ni identité ne sont inventés.

La politique de réponse exige en plus l'autorisation explicite du blocage automatique, une source vérifiée et récente et une IP autorisée par la configuration. Les IP protégées, les résolveurs DNS et le Cloud ne doivent pas être isolés. La décision et son résultat sont journalisés. Le composant ne garantit pas la détection de toutes les méthodes d'authentification ni de tous les formats OpenSSH.

Sur Linux, le blocage ciblé exige UFW déjà actif. Sur Windows, l'exécuteur utilise des règles natives `netsh` et vérifie leurs champs ; une sortie non interprétable, notamment une localisation non prise en charge, ne vaut jamais réussite. Deux règles précises, entrante et sortante, doivent être retrouvées après création. Un code de retour nul seul ne suffit pas. Un échec ou délai conserve son reçu et tente le retrait ciblé, puis vérifie ce retrait. Cela prouve la configuration des règles, pas l'interruption de tous les flux existants : les connexions déjà établies et les autres couches réseau demandent un essai effectif.

Un blocage automatique porte une échéance persistée avant l'appel natif (`auto_block_seconds`, 600 secondes par défaut). **Le service doit fonctionner pour appliquer le retrait à échéance** : UFW n'offre pas ici de minuteur autonome. Après un arrêt de l'application, le service reprend les reçus expirés et vérifie le retrait de ses propres règles. L'interface doit conserver l'alerte si le retrait échoue. Aucun retrait global du pare-feu n'est utilisé.

### Pourquoi un fichier auth.log ne suffit pas à autoriser un blocage

`auth_log_paths` permet la lecture bornée de fichiers d'authentification choisis par l'opérateur, sur Linux ou macOS. Même si le fichier appartient à root, un tag syslog peut être produit par une application qui n'est pas sshd. Ces lignes restent donc des **indices non vérifiés** : alerte visible, jamais permission automatique d'isoler l'IP. Les métadonnées journald préfixées `_` sont, elles, attribuées par le service de journalisation.

Les fichiers texte commencent à leur fin lors de la première configuration : l'historique n'est pas présenté comme une nouvelle attaque. Le curseur reprend après redémarrage ; les rotations, troncatures et réécritures au point de reprise génèrent un signal de couverture. Les lignes trop longues et les lectures dépassant le budget sont signalées. Une ligne incomplète attend le passage suivant. Les sorties natives sont bornées ; un délai, un accès refusé ou un curseur expiré donnent un **défaut de couverture**, pas un état « tout va bien ». Un curseur journald devenu introuvable n'est pas réinitialisé silencieusement : l'opérateur doit investiguer puis réinitialiser explicitement le fichier d'état privé si nécessaire.

Le capteur Windows Security Event Log n'est pas implémenté dans cette version. La surveillance de ressources et de fichiers disponible sur Windows ne remplace pas ce collecteur.

## Règles d'audit Linux explicites

`sawm_defense.kernel.audit_plan(config, state_dir)` prépare un plan sans rien installer. `kernel_audit_paths` définit jusqu'à 32 répertoires ; en son absence, le plan utilise `monitor_paths`. Les chemins doivent exister, être absolus, canoniques, sans liens symboliques ni caractères de commande. La racine `/` entière est refusée.

`install_audit(config, state_dir, approved=True)` demande un processus déjà administrateur Linux. Il n'invoque pas `sudo` et n'installe aucun paquet à la volée. Il exige `auditctl` protégé, auditd actif, audit modifiable et absence de règles `never` susceptibles de neutraliser la collecte. Il ajoute seulement les règles prévues, vérifie leur présence et sauvegarde le manifeste privé `sawm-defense-audit.rules`.

Exemple de règle générée pour un répertoire choisi :

```text
-a always,exit -F arch=b64 -F dir=/srv/application -F perm=wa -k sawm_<identifiant>
```

Sur x86-64, le plan ajoute la variante b32. `w` désigne les écritures, `a` les changements d'attributs. Le filtre de répertoire permet aux événements audit du noyau d'indiquer le processus et les identifiants disponibles, y compris l'utilisateur de connexion quand `loginuid` est correctement établi. Cela n'identifie pas automatiquement une personne : comptes partagés, délégation et élévation de droits nécessitent une investigation.

Les règles sont **actives jusqu'au redémarrage**. L'application n'écrit pas automatiquement dans `/etc/audit/rules.d`, ne désactive pas l'audit et ne remplace jamais les règles de l'institution. Pour la persistance, l'administrateur revoit le manifeste, l'intègre à sa politique auditd et le valide au redémarrage. Ne pas appliquer un fichier arbitraire sans examen : auditctl accepte aussi des directives globales.

En cas d'échec, seules les règles exactes ajoutées par l'invocation font l'objet d'un retrait ; le résultat précise si ce retrait a abouti. Aucune commande `auditctl -D` n'est émise.

**Limite du raccordement actuel :** les événements auditd ne sont pas encore importés dans le tableau de bord. Ils restent consultables avec les outils natifs, par exemple `ausearch -k <clé du manifeste> -i`. L'installation vérifiée des règles ne constitue pas un test réel de chaque opération surveillée. Les sous-montages, io_uring, lectures, réseau et événements perdus demandent une couverture complémentaire. Le noyau eBPF/LSM n'est ni chargé ni modifié par ce composant.

## Preuves et périmètre

Les tests logiciels couvrent des journaux fictifs, la reprise des curseurs, les rotations, les doublons, les horodatages périmés, des tags falsifiés et les délais du lecteur. Les tests auditctl remplacent l'exécuteur privilégié par un témoin : aucun pare-feu ni noyau de la machine de développement n'est modifié.

Cette intégration apporte des éléments de contrôle et de preuve utiles pour une démarche ISO/IEC 27001 et une base technique CIS. Elle ne certifie ni l'organisation ni l'application. La gouvernance, le périmètre, les droits, la gestion des incidents et les tests sur l'infrastructure cible restent à documenter. Un root hostile ou un noyau compromis peut altérer les capteurs locaux ; la conservation de preuves sur un domaine d'administration distinct reste nécessaire pour ce scénario.

Références primaires : [champs journald](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html), [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html), [manuel auditctl du projet Linux Audit](https://github.com/linux-audit/audit-userspace/blob/master/docs/auditctl.8), [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html).
