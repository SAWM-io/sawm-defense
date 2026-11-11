# SAWM Defense

[![Tests et paquets](https://github.com/SAWM-io/sawm-defense/actions/workflows/build.yml/badge.svg)](https://github.com/SAWM-io/sawm-defense/actions/workflows/build.yml)

[Télécharger la version pilote](https://github.com/SAWM-io/sawm-defense/releases) · [Guide pas à pas](docs/INTERFACE.md) · [Serveurs / CLI](docs/CLI.md)

**Votre agent surveille, signale et intervient dans les limites que vous lui confiez.**

Une application de défense pour **macOS, Linux et Windows**, le même service en **CLI pour les serveurs**. SAWM Defense relie les observations du poste à **SAWM Cloud**, à la mémoire **Basira**, au rappel **TSST** et au classement **ODVL**. Configurez votre espace et vos autorisations : la veille fonctionne ensuite sans attendre une question dans le chat.

**Version 0.2.0 — pilote logiciel.** Le code de collecte, d’analyse et de contrôle est commun à l’application et à la CLI. Le client utilise les API publiques : les moteurs privés SAWM, Basira, TSST et ODVL ne sont pas distribués. La matrice de couverture ci-dessous distingue les fonctions du client des validations système et Cloud à réaliser dans votre environnement.

## Ce que l’agent fait pour vous

- **Veiller en continu** : fichiers, processus, connexions visibles et consommation CPU/RAM, avec état réel des capteurs et limites de couverture.
- **Examiner les téléchargements** : repérer les fichiers nouveaux ou modifiés, attendre leur stabilité, inspecter leur structure et appeler l’antivirus local lorsqu’il existe.
- **Inspecter même sans antivirus** : caractéristiques du fichier, en-têtes, type réel, métadonnées, archives et informations de signature disponibles. Un résultat douteux produit une alerte, pas une déclaration infondée de malware.
- **Relier les signaux** : suivre les événements, retrouver les précédents autorisés avec Basira/TSST, les classer avec ODVL et faire analyser les alertes par SAWM en arrière-plan.
- **Alerter sans demande préalable** : boîte de notifications persistante et notification native du système. Livraison, échec et accusé de lecture restent distincts.
- **Intervenir selon votre mandat** : quarantaine, arrêt ciblé et blocage IP, soumis à des preuves locales vérifiées, des cibles attribuées et vos périmètres. Vous choisissez séparément les interventions automatiques.
- **Repérer les tentatives SSH répétées** : seuil et fenêtre temporelle, provenance du journal, adresses protégées ; blocage temporaire possible à partir d’une source Linux fiable et d’une autorisation explicite.
- **Recevoir des missions** : scan, inventaire, analyse, rapport ; file persistante, identité de la session demandeuse, état et résultat. Les actions et restaurations passent par le même contrôle local.
- **Expliquer et rendre compte** : dialogue SAWM, journal d’actions, refus, reçus Cloud, jetons lorsque fournis et exports HTML/JSON.
- **Continuer localement pendant une panne Cloud** : observations et tâches restent conservées ; la collecte et les protections locales autorisées ne dépendent pas d’une réponse immédiate du modèle.

La résilience concerne la surveillance et la livraison des observations. Le programme ne répare pas une liaison physique coupée. Une détection antivirus vérifiée est distincte d’un indice structurel ou d’une hypothèse SAWM.

## Télécharger et lancer — sans installer Python

Ouvrez la [version pilote **v0.2.0**](https://github.com/SAWM-io/sawm-defense/releases/tag/v0.2.0), puis choisissez l’archive de votre ordinateur dans **Assets**. C’est une préversion destinée aux pilotes clients. [Toutes les versions](https://github.com/SAWM-io/sawm-defense/releases).

| Votre ordinateur | Archive à télécharger |
| --- | --- |
| Mac Apple Silicon — puces M1, M2, M3, M4… | `SAWM-Defense-0.2.0-macos-arm64.zip` |
| Mac avec processeur Intel | `SAWM-Defense-0.2.0-macos-x86_64.zip` |
| Linux x86-64 — Ubuntu 24.04 ou environnement compatible | `SAWM-Defense-0.2.0-linux-x86_64.tar.gz` |
| Windows x86-64 | `SAWM-Defense-0.2.0-windows-x86_64.zip` |

**Ces archives contiennent l’application et son environnement d’exécution. Aucun Python à installer.** Ne choisissez pas les liens GitHub « Source code » pour une installation prête à lancer. Gardez le dossier de l’application complet : les bibliothèques qui l’accompagnent sont nécessaires.

Chaque paquet publié fournit un fichier `START-HERE.txt`, la documentation et sa preuve `PACKAGED-VALIDATION.json`. Cette dernière décrit les essais réellement exécutés sur le **binaire de cet OS**, avec des fichiers de contrôle inoffensifs. Elle ne vaut pas validation d’une intervention réelle sur le pare-feu ni d’un compte Cloud client. Les résultats de construction courants sont accessibles par le badge en haut de cette page ; aucun résultat CI en cours n’est présenté comme acquis.

### Sur Mac — Apple Silicon ou Intel

1. Décompressez le ZIP correspondant à votre processeur.
2. Glissez **SAWM Defense.app** dans **Applications**.
3. Ouvrez l’application, puis **Réglages** pour connecter votre compte et choisir vos autorisations.

La préversion utilise une signature ad hoc, sans notarisation Apple. Si macOS demande une vérification, examinez l’origine du paquet et les indications du système ; ne désactivez pas les protections du Mac globalement.

Pour utiliser ce même programme en terminal :

```bash
"/Applications/SAWM Defense.app/Contents/MacOS/SAWM Defense" doctor
"/Applications/SAWM Defense.app/Contents/MacOS/SAWM Defense" watch
```

### Sur Windows

1. Extrayez entièrement le ZIP dans le dossier de votre choix.
2. Ouvrez le sous-dossier **sawm-defense**.
3. Double-cliquez sur **sawm-defense.exe**.

Il s’agit d’une application portable : aucun installateur Python et aucun accès administrateur ne sont nécessaires pour ouvrir l’interface. Les interventions privilégiées restent soumises aux droits du système. Cette préversion ne porte pas encore de signature Authenticode commerciale.

Depuis PowerShell, dans le dossier extrait :

```powershell
.\sawm-defense\sawm-defense.exe doctor
.\sawm-defense\sawm-defense.exe watch
```

### Sur Linux — poste ou serveur

Décompressez l’archive, puis ouvrez son dossier :

```bash
tar -xzf SAWM-Defense-0.2.0-linux-x86_64.tar.gz
cd SAWM-Defense-0.2.0-linux-x86_64
./sawm-defense/sawm-defense gui
```

L’interface nécessite une session graphique et les bibliothèques natives disponibles sur le système cible. Le binaire vise **Ubuntu 24.04 x86-64** ; sa compatibilité avec une autre distribution doit être vérifiée.

Sur un serveur sans interface graphique, utilisez le même exécutable :

```bash
./sawm-defense/sawm-defense doctor
./sawm-defense/sawm-defense watch
```

Aucun pilote noyau ni règle pare-feu ne sont installés par l’extraction de l’archive. Les fonctions Linux supplémentaires se configurent explicitement : [guide CLI](docs/CLI.md) et [guide noyau](docs/KERNEL.md).

### Au premier lancement

La veille locale et l’inspection des téléchargements démarrent. **Aucune intervention ni transmission Cloud n’est autorisée par défaut.** Ouvrez **Réglages** pour connecter votre compte, choisir les dossiers et autoriser les actions souhaitées. **Veille & missions** présente les alertes et les tâches. Un nouveau ZIP ne remplace pas automatiquement une ancienne application : fermez l’ancienne version avant de la remplacer.

<details>
<summary><strong>Développeurs : installation depuis les sources et construction des paquets</strong></summary>

Cette voie est facultative et nécessite Python 3.12 avec Tcl/Tk :

```bash
git clone https://github.com/SAWM-io/sawm-defense.git
cd sawm-defense
python3.12 -m venv .venv
# Linux/macOS : source .venv/bin/activate
# Windows : .venv\Scripts\Activate.ps1
python -m pip install '.[dev]'
python -m sawm_defense
python -m pytest -q
python packaging/build.py
```

L’installateur source Linux `packaging/install-linux.sh` crée une entrée de menu utilisateur. Sur Ubuntu, il nécessite `python3`, `python3-venv` et `python3-tk`. Sur Windows, `packaging/install-windows.ps1` crée un raccourci dans le menu Démarrer et requiert un Python avec Tcl/Tk.

Le workflow `.github/workflows/build.yml` construit nativement les quatre variantes, exécute les vérifications du binaire, puis prépare les archives et leurs empreintes SHA256 avec `packaging/release_bundle.py`. PyInstaller doit fonctionner sur l’OS cible ; un paquet Mac ne s’exécute pas sous Windows. Les archives ne distribuent pas les moteurs privés du Cloud.

</details>

## Première configuration

1. **Veille locale** : vérifiez les chemins et l’option Téléchargements. La surveillance au lancement et l’inspection automatique sont activables indépendamment des interventions. Le Cloud peut rester désactivé.
2. **Espace Cloud dédié** : dans [Basira Cloud](https://basira.sawm.io/espace), créez une mémoire pour ce poste et une clé limitée à ce périmètre. Les scopes utilisés sont `events:write`, `jobs:read`, `memory:recall`, `tsst:recall`, `odvl:rank`, `sawm:run`, avec les droits correspondants sur l’entité.
3. **Connexion** : renseignez URL, espace, entité et clé, puis vérifiez l’accès. La vérification TSST/ODVL n’est pas un essai d’écriture ou d’inférence SAWM ; ces opérations sont vérifiées lors de leur utilisation.
4. **Partage explicite** : activez séparément les fonctions Cloud et l’envoi de métadonnées. Noms, chemins, empreintes et attribution peuvent entrer dans le contexte. Les contenus bruts ne sont pas automatiquement téléversés.
5. **Mandat d’action** : choisissez les permissions de quarantaine, arrêt et blocage, les cibles autorisées et les exclusions. L’interface confirme l’élargissement des permissions. Une réponse du modèle ne modifie jamais ce mandat.
6. **Service permanent** : après vérification du comportement, installez volontairement le démarrage supervisé depuis les réglages ou la CLI. Fermer une console ne doit pas être confondu avec arrêter un service séparé.

Les clés résident dans le coffre natif, liées à la destination Cloud. Sans coffre disponible, une clé en mémoire est possible pour une session ; aucune clé n’est écrite en clair. Sur un serveur sans session de coffre, préparez la gestion des secrets avec l’administrateur.

Pour une session serveur sans coffre natif, configurez d’abord l’espace et l’entité, puis lancez `sawm-defense watch --prompt-key` : la saisie est masquée et la clé reste en mémoire jusqu’à l’arrêt. Elle n’est pas passée en argument ni conservée pour un redémarrage automatique.

## De l’observation à l’action

```mermaid
flowchart LR
    OS[Poste ou serveur] --> Sensors[Fichiers · processus · réseau · journaux]
    Sensors --> Queue[Journal et files persistantes]
    Queue --> Alerts[Notifications et revue humaine]
    Queue -->|partage et budget autorisés| Basira[Basira Cloud]
    Basira --> TSST[Rappel TSST]
    TSST --> ODVL[Classement ODVL]
    ODVL --> SAWM[Analyse SAWM en arrière-plan]
    SAWM --> Policy[Mandat local + preuve actuelle + cible]
    Local[Antivirus et provenance système] --> Policy
    Policy -->|autorisé| Action[Quarantaine · arrêt ciblé · blocage temporaire]
    Policy -->|incertain ou refusé| Alerts
    Action --> Check[Reçu et vérification du résultat]
    Check --> Queue
    Human[Missions utilisateur typées] --> Queue
```

Le modèle aide à analyser. Le système local vérifie l’autorité et exécute les seules opérations prévues. Un texte provenant d’un fichier, d’un journal ou d’une réponse Cloud reste une donnée : il ne devient jamais une commande shell. Un souvenir historique ne prouve pas l’état actuel d’une cible.

### Télécharger n’est pas exécuter

Le programme inspecte les fichiers observés sur disque. Il ne garantit pas l’interception de chaque téléchargement **avant** écriture ou exécution. Sans antivirus, `no_indicator` signifie « aucun indicateur reconnu dans les contrôles réalisés », pas « fichier sain ». `suspicious` demande une revue ; `incomplete` indique une limite. L’inspection seule ne fournit pas la preuve antivirus exigée pour une intervention automatique destructrice.

## Couverture par système

| Fonction | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Fichiers sélectionnés, empreintes, CPU/RAM, interface | Essais locaux réels ; preuve du paquet pour chaque architecture | Vérifications du binaire dans la preuve jointe ; exploitation client à valider | Vérifications du binaire dans la preuve jointe ; exploitation client à valider |
| Processus et connexions | Selon droits ; certaines mesures réseau peuvent être refusées | Selon droits | Selon droits |
| Inspection structurelle de fichiers | Contrôles locaux bornés | Contrôles portables | Contrôles portables |
| Antivirus à signatures | ClamAV s’il est installé | ClamAV s’il est installé | Defender ou ClamAV selon disponibilité |
| Notifications | Intégration native selon autorisations OS | Service de notifications si disponible ; boîte locale sinon | Intégration native selon environnement ; boîte locale sinon |
| Quarantaine/restauration | Essais sur fichiers temporaires inoffensifs | Implémentation portable | Implémentation portable |
| Blocage IP | Non implémenté dans ce pilote | UFW déjà actif et droits adéquats | Pare-feu Windows et droits adéquats |
| Échecs SSH attribués par source système fiable | Pas de source native équivalente validée | Journal système Linux, activation explicite | Pas de source native équivalente validée |
| Collecte noyau supplémentaire | Pas d’extension Endpoint Security distribuée | Règles audit Linux sur périmètre choisi ; traces consultables nativement, pas encore importées dans l’application | Pas de pilote noyau distribué |
| Démarrage utilisateur | LaunchAgent | systemd utilisateur | Tâche planifiée à l’ouverture de session |

L’agent ne réside pas dans le noyau. Il emploie les interfaces du système selon les permissions. La lecture d’un binaire ne donne pas son code source. Les inventaires, sondages et signatures n’établissent pas une absence universelle de malware ; les opérations très brèves peuvent échapper au sondage.

## ISO 27001, CIS et preuves

Le dossier [ISO 27001 / CIS](docs/ISO27001-CIS.md) relie les fonctions aux thèmes de contrôle, aux preuves produites et aux obligations restant à assurer dans l’organisation. Références : ISO/IEC 27001:2022 et son amendement de 2024, CIS Controls v8.1. Cette contribution technique n’est pas une certification ISO ni une conformité complète du parc.

Les tests automatisés distinguent les opérations locales réellement exécutées, les API simulées, les commandes OS contrôlées sans exécution et les mesures natives restant à faire. Aucun accès Cloud client réel n’a été utilisé dans la campagne locale de cette application. Consultez [les résultats et la méthode](docs/VALIDATION.md) avant une démonstration commerciale.

## Budget, conservation et exploitation

Le budget par défaut est **4 opérations Cloud par heure**. Une opération peut provoquer plusieurs requêtes HTTP ; le journal montre les appels et les jetons réellement fournis. Un budget ou un crédit insuffisant ne doit pas se transformer en succès simulé.

Les observations et tâches en attente sont conservées. Une panne longue ou un flot d’événements peut augmenter le stockage : surveillez l’espace en exploitation. Le journal chaîné détecte des incohérences, mais un journal entièrement local n’est pas inviolable face à l’administrateur de l’hôte. Les quarantaines attendent une décision de restauration ou de traitement.

**Documentation :** [interface](docs/INTERFACE.md) · [CLI](docs/CLI.md) · [interfaces noyau](docs/KERNEL.md) · [architecture](docs/ARCHITECTURE.md) · [ISO/CIS](docs/ISO27001-CIS.md) · [validation](docs/VALIDATION.md).

Le retrait d’un blocage temporaire est réalisé par le service à l’échéance, puis rattrapé à la reprise si nécessaire. Une règle UFW ou Windows peut donc subsister pendant un arrêt de l’agent ; ce délai n’est pas une expiration garantie par le noyau.
