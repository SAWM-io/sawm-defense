# SAWM Defense

[![Tests et paquets](https://github.com/SAWM-io/sawm-defense/actions/workflows/build.yml/badge.svg)](https://github.com/SAWM-io/sawm-defense/actions/workflows/build.yml)

[Télécharger la version pilote](https://github.com/SAWM-io/sawm-defense/releases) · [Guide pas à pas](docs/INTERFACE.md) · [Serveurs / CLI](docs/CLI.md)

**Votre agent surveille, signale et intervient dans les limites que vous lui confiez.**

Une application de défense pour **macOS, Linux et Windows**, le même service en **CLI pour les serveurs**. SAWM Defense relie les observations du poste à **SAWM Cloud**, à la mémoire **Basira**, au rappel **TSST** et au classement **ODVL**. Configurez votre espace et vos autorisations : la veille fonctionne ensuite sans attendre une question dans le chat.

**Version 0.2.1 — pilote logiciel.** Le code de collecte, d’analyse et de contrôle est commun à l’application et à la CLI. Le client utilise les API publiques : les moteurs privés SAWM, Basira, TSST et ODVL ne sont pas distribués. La matrice de couverture ci-dessous distingue les fonctions du client des validations système et Cloud à réaliser dans votre environnement.

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

## Télécharger et lancer

**Téléchargez le paquet de votre ordinateur : aucun Python à installer.** La [version pilote v0.2.1](https://github.com/SAWM-io/sawm-defense/releases/tag/v0.2.1) contient l’application graphique et la CLI dans le même paquet.

| Votre ordinateur | Téléchargement direct | Pour commencer |
| --- | --- | --- |
| **Windows x86-64** | [ZIP Windows](https://github.com/SAWM-io/sawm-defense/releases/download/v0.2.1/SAWM-Defense-0.2.1-windows-x86_64.zip) | Extraire, puis ouvrir `sawm-defense/sawm-defense.exe` |
| **Linux x86-64 — Ubuntu 24.04** | [Archive Linux](https://github.com/SAWM-io/sawm-defense/releases/download/v0.2.1/SAWM-Defense-0.2.1-linux-x86_64.tar.gz) | Extraire, puis lancer l’application ou la CLI |
| **Mac Apple Silicon — M1, M2, M3, M4…** | [ZIP Mac Apple Silicon](https://github.com/SAWM-io/sawm-defense/releases/download/v0.2.1/SAWM-Defense-0.2.1-macos-arm64.zip) | Copier **SAWM Defense.app** dans **Applications** |
| **Mac Intel** | [ZIP Mac Intel](https://github.com/SAWM-io/sawm-defense/releases/download/v0.2.1/SAWM-Defense-0.2.1-macos-x86_64.zip) | Copier **SAWM Defense.app** dans **Applications** |

Chaque archive comprend les instructions `START-HERE.txt`, la documentation et `PACKAGED-VALIDATION.json`, lié à l’exécutable vérifié. Les empreintes SHA256 sont disponibles sur la page de la version.

### Windows

1. Téléchargez le ZIP Windows, puis choisissez **Extraire tout**.
2. Dans le dossier extrait, ouvrez **sawm-defense**, puis **sawm-defense.exe**.
3. Ouvrez **Réglages** pour connecter votre compte et choisir vos autorisations.

**Gardez le dossier `sawm-defense` complet** : déplacer uniquement le fichier `.exe` empêcherait le programme de retrouver ses bibliothèques. Vous pouvez créer un raccourci vers cet exécutable.

Pour un serveur ou une utilisation en terminal, ouvrez PowerShell dans le dossier `SAWM-Defense-0.2.1-windows-x86_64` :

```powershell
.\sawm-defense\sawm-defense.exe doctor
.\sawm-defense\sawm-defense.exe watch
```

### Mac — Apple Silicon ou Intel

1. Téléchargez le ZIP correspondant à votre Mac, puis décompressez-le.
2. Glissez **SAWM Defense.app** dans **Applications**.
3. Ouvrez l’application, puis **Réglages** pour connecter votre compte et choisir vos autorisations.

Pour utiliser le même programme en terminal :

```bash
"/Applications/SAWM Defense.app/Contents/MacOS/SAWM Defense" doctor
"/Applications/SAWM Defense.app/Contents/MacOS/SAWM Defense" watch
```

### Linux — application ou serveur

Après avoir téléchargé l’archive Linux, ouvrez un terminal dans le dossier qui la contient :

```bash
tar -xzf SAWM-Defense-0.2.1-linux-x86_64.tar.gz
cd SAWM-Defense-0.2.1-linux-x86_64
./sawm-defense/sawm-defense gui
```

L’application demande une session graphique. Pour un serveur sans interface graphique, remplacez la dernière commande par `./sawm-defense/sawm-defense watch`. La commande `./sawm-defense/sawm-defense doctor` vérifie la configuration et les capteurs accessibles. Gardez le dossier de l’application complet.

**Version pilote :** les paquets ne portent pas de signature d’éditeur commercial ; l’application Mac utilise une signature ad hoc et n’est pas notarisée par Apple. Vérifiez l’origine et l’empreinte du téléchargement, puis suivez les indications de votre système ou de votre administrateur sans désactiver globalement ses protections.

### Au premier lancement

La veille locale et l’inspection des téléchargements démarrent. **Aucune intervention ni transmission Cloud n’est autorisée par défaut.** Ouvrez **Réglages** pour connecter votre compte, choisir les dossiers et autoriser les actions souhaitées. **Veille & missions** présente les alertes et les tâches. Fermez l’ancienne version avant de remplacer l’application.

### Ce qui a été vérifié dans les paquets

Les exécutables passent des contrôles CLI sur fichiers de test inoffensifs : observation, inspection, quarantaine manuelle et restauration, journal, mission et rapport. Un contrôle distinct vérifie l’ouverture d’une fenêtre graphique rattachée au processus lancé. **Ce contrôle de fenêtre ne teste pas tous les clics métier.** Il ne valide pas non plus une intervention réelle sur le pare-feu ou les appels à votre compte Cloud. [Méthode et périmètre des vérifications](docs/VALIDATION.md).

<details>
<summary><strong>Développeurs : installation depuis les sources, tests et construction</strong></summary>

Cette voie est facultative ; les paquets ci-dessus embarquent leur environnement Python. Pour travailler sur les sources, utilisez **Python 3.12 ou ultérieur avec Tcl/Tk**, puis récupérez le dépôt :

```bash
git clone https://github.com/SAWM-io/sawm-defense.git
cd sawm-defense
```

**Linux Ubuntu** — installation dans le compte utilisateur, avec entrée au menu Applications :

```bash
sudo apt install python3 python3-venv python3-tk
sh packaging/install-linux.sh
~/.local/share/sawm-defense-app/sawm-defense gui
```

**Windows** — installez Python avec Tcl/Tk et son lanceur, puis depuis PowerShell à la racine des sources :

```powershell
powershell -NoProfile -File .\packaging\install-windows.ps1
```

Ouvrez ensuite **SAWM Defense** depuis le menu Démarrer. Le lanceur CLI est `"$env:LOCALAPPDATA\SAWM Defense App\SAWM Defense.cmd"`. Respectez les règles d’exécution de scripts de votre organisation.

**macOS** — depuis les sources :

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m sawm_defense gui
```

**Tests et construction**, dans l’environnement Python choisi :

```bash
python -m pip install '.[dev]'
python -m pytest -q
python packaging/build.py
```

Le workflow `.github/workflows/build.yml` construit sur chaque OS cible, vérifie l’exécutable et la fenêtre graphique, puis prépare les archives et empreintes SHA256 avec `packaging/release_bundle.py`. PyInstaller ne transforme pas un paquet Mac en programme Windows. Les archives ne distribuent aucun moteur privé du Cloud.

L’installation source ne donne aucun droit administrateur au modèle et n’active aucune règle pare-feu. Les fonctions privilégiées se configurent séparément : [guide CLI](docs/CLI.md), [guide noyau](docs/KERNEL.md).

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
| Paquet natif : contrôles CLI et ouverture de fenêtre | Apple Silicon et Intel | Ubuntu 24.04 x86-64 | Windows x86-64 |
| Fichiers sélectionnés, empreintes, CPU/RAM | Collecte selon périmètre et droits | Collecte selon périmètre et droits | Collecte selon périmètre et droits |
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
