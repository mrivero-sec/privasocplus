# Déploiement privasoc+

La composition de base est locale. Le modèle distant demande à la fois le profil
`frontier` et le fichier d'activation `compose.frontier.yml`. Le triage distant reste
une action humaine ; aucune escalade automatique n'est ajoutée.
Le repli automatique est désactivé dans cette composition et la passe résiduelle locale
est imposée avant les appels distants, même si le `.env` source avait d'autres réglages.

## Préparer

Depuis `deploy/`, copier `.env.example` en `.env`, garder les chemins par défaut des deux
paquets (`../packages/privasoc`, `../packages/gateway`) et renseigner `PRIVASOC_API_TOKEN` avec la même valeur que dans le `.env` de privasoc.
Ne pas copier la clé fournisseur dans ce dernier. Vector ne reçoit que le jeton
d'ingestion, pas les secrets du coffre ou du fournisseur. Ses configurations doivent
utiliser `PRIVASOC_INGEST_URL` et `PRIVASOC_API_TOKEN`.

Les dossiers `data/` et `vector/` doivent être préparés par privasoc et accessibles à
son utilisateur de conteneur. Pour une reproduction exacte, fixer les images par digest.
L'image Ollama par défaut suit `latest` ; aucun gain GPU n'est présumé : l'accélération
GPU nécessite une configuration propre à la machine.

```bash
docker compose --env-file .env config --quiet
docker compose --env-file .env up -d --build
docker compose --env-file .env exec local-model ollama pull qwen3:8b
```

Adapter le dernier modèle si `LOCAL_MODEL` a été changé. Il faut télécharger les poids
avant le premier triage ; le téléchargement ne contient aucun log. Le premier démarrage
n'est pas une validation des parseurs ou du triage.

## Activer les avis distants

Renseigner `SOVGATE_HMAC_SECRET`, `SOVGATE_PRIVASOC_KEY`, `EXTERNAL_API_KEY` et
`FRONTIER_MODEL` dans le `.env` de déploiement, puis :

```bash
docker compose --env-file .env --profile frontier -f docker-compose.yml -f compose.frontier.yml config --quiet
docker compose --env-file .env --profile frontier -f docker-compose.yml -f compose.frontier.yml up -d --build
```

La même valeur `FRONTIER_MODEL` configure privasoc et le modèle réellement appelé par
sovgate. GLiNER est installé et activé ; si ses dépendances ou ses poids manquent,
sovgate ne démarre pas. Le premier téléchargement des poids requiert Internet.
Le démarrage sain de sovgate conditionne celui de privasoc dans cette variante.

La passerelle exige un manifeste des jetons IP/MAC issus du coffre local. Ce manifeste
est retiré avant l'appel fournisseur. Cela bloque aussi une adresse oubliée dans `10/8`
ou une MAC réelle qui commence par `02`. Les noms résiduels et les quasi-identifiants
restent des limites à mesurer ; la configuration ne garantit pas une anonymisation totale.

## Réseaux et accès

- privasoc est relié uniquement à trois réseaux internes : ingestion, modèle local et
  passerelle. Il n'a pas de réseau de sortie Internet dans cette composition.
- Vector partage seulement le réseau d'ingestion ; il n'atteint pas sovgate.
- Seule la passerelle possède le réseau de sortie fournisseur. Le serveur local possède
  un réseau distinct pour télécharger ses poids : il reste un composant local de confiance.
- Interface et syslog sont publiés sur loopback par défaut. Ouvrir `SYSLOG_BIND` au LAN
  est une décision explicite de l'opérateur, avec les règles pare-feu adaptées.

Cette composition utilise un serveur Ollama interne, pas automatiquement le serveur
Ollama déjà installé sur l'hôte ou sur le LAN. Toute adaptation réseau doit préserver
l'absence de sortie directe de privasoc et être vérifiée sur la machine cible.

## Validation opérationnelle restante

Contrôler un démarrage complet, une ingestion réelle, le triage local, un refus de fuite,
un avis distant synthétique, puis la conservation du triage lors d'un arrêt de sovgate.
Vérifier également, depuis privasoc, l'accès au modèle local et le refus d'une connexion
Internet directe. La validation de syntaxe Compose et les tests simulés ne remplacent
pas ces contrôles. Ne pas envoyer les fixtures Elastic au fournisseur.
