# Utiliser l’application SAWM Defense

L’interface native et la commande serveur utilisent le même service local, les mêmes règles et le même journal. L’application n’ouvre pas de serveur Web local.

## Première connexion

1. Ouvrez **Réglages** et saisissez l’URL de l’API, l’identifiant de votre espace Basira et celui de la mémoire destinée à ce poste.
2. Renseignez votre clé API. Par défaut, elle est conservée dans le trousseau sécurisé du système. Décochez cette option pour une clé qui ne subsiste que pendant cette session. Si le trousseau est indisponible, l’application signale l’échec et n’écrit pas la clé en clair.
3. Activez le dialogue Cloud. L’envoi des métadonnées d’observation est un consentement séparé : noms de fichiers, chemins, adresses réseau et informations d’attribution peuvent être transmis à votre espace. Le contenu des fichiers n’est pas envoyé automatiquement.
4. Choisissez **Enregistrer**, puis **Vérifier l’accès Cloud**. Le résultat affiché vient des API ; une configuration saisie n’est pas présentée comme une connexion vérifiée.
5. Ajoutez explicitement vos dossiers à surveiller, enregistrez, puis démarrez la surveillance depuis **Vue d’ensemble**.

La clé doit avoir les autorisations appropriées dans votre environnement Cloud. L’application ne crée pas de droits administrateur et ne contourne pas l’approbation des comptes.

## Comprendre la console

- **Vue d’ensemble** : état du service, accès Cloud, moteur antivirus réellement disponible, permissions et courbes CPU/RAM de la session. Une mesure manquante n’est pas transformée en zéro.
- **Observations** : événements horodatés, filtres, preuve structurée et identifiant. Sélectionnez un événement pour demander l’analyse de SAWM ou examiner une intervention manuelle.
- **Système** : processus et connexions visibles avec les droits actuels. L’inventaire des logiciels est lancé à la demande, pas à chaque rafraîchissement.
- **Parler à SAWM** : questionnez l’agent. Ses réponses sont des analyses ; elles ne modifient pas les permissions locales. Le contexte des événements est transmis seulement si l’option correspondante est activée.
- **Réglages** : périmètres, clé, budget d’opérations Cloud, durée de conservation et démarrage automatique.
- **Journal** : actions proposées ou exécutées, refus, résultats et appels Cloud. Les jetons et durées ne sont affichés que lorsqu’ils sont effectivement disponibles.

Les séparateurs des panneaux sont déplaçables à la souris. Les détails restent sélectionnables pour pouvoir les copier. Le journal conserve les reçus même après fermeture de la fenêtre.

## Choisir les interventions

La quarantaine automatique nécessite une détection antivirus locale vérifiée sur le fichier concerné, une autorisation enregistrée et un chemin dans le périmètre. Une hausse de CPU, un nom de fichier ou une proposition du Cloud ne suffit pas.

Dans cette version, arrêter un processus et bloquer une IP nécessitent une confirmation humaine et des cibles explicitement autorisées dans les réglages. L’exécuteur revérifie leur identité et les droits système au moment de l’action. Une plateforme non prise en charge renvoie un refus explicite.

Une action de quarantaine ou de blocage réseau terminée peut être sélectionnée dans le journal pour demander son retour arrière. La restauration n’écrase jamais un fichier déjà présent. Un processus arrêté ne peut pas être ressuscité automatiquement.

## Analyse antivirus

Le bouton **Analyser un fichier** utilise un moteur déjà installé : ClamAV ou Microsoft Defender selon le système. L’écran indique clairement quand aucun moteur n’est disponible. Les signatures et la configuration du moteur restent celles de l’administrateur ; la surveillance des fichiers ne remplace pas un moteur antivirus.

## Service et rapports

Le démarrage à l’ouverture de session est une option explicite. Lorsqu’un service externe au processus de l’interface surveille déjà ce profil, la console affiche **Géré par le service utilisateur** et consulte ses observations. Fermer cette console n’arrête pas ce service séparé. Les réglages de démarrage permettent de le retirer.

**Rapport d’activité** produit un fichier HTML lisible ou un export JSON. Un rapport peut contenir des noms d’utilisateur, chemins et adresses : son partage est réservé aux personnes autorisées. La chaîne de hachage locale permet de détecter des incohérences ; elle n’est pas une attestation indépendante d’un hôte entièrement compromis.

Le budget affiché est un nombre d’**opérations** Cloud par heure. Une opération peut contenir plusieurs requêtes HTTP et la consommation facturée reste celle des API. Une coupure Cloud conserve la surveillance locale et les événements en attente ; elle n’implique pas que le poste répare physiquement sa connexion réseau.
