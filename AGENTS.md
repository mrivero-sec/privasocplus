# Instructions pour les assistants IA qui travaillent sur ce dossier

Ce fichier s'adresse à tout assistant (ChatGPT, Codex, Claude...). Ce dépôt est le **seul** projet (DECISIONS PD29) : code, décisions et suivi y sont tous ; il doit suffire à comprendre le projet et à reprendre le travail.

## 1. Lire dans cet ordre

1. [README.md](README.md) : ce qu'est privasoc+, où on en est, carte des fichiers.
2. [docs/PROGRESS.md](docs/PROGRESS.md) : ce qui est fait, sur quelles branches, comment le vérifier, prochaines actions.
3. [docs/CONTEXT.md](docs/CONTEXT.md) : les deux paquets (`packages/privasoc`, `packages/gateway`), leurs mécanismes et les identifiants de décision cités.
4. [docs/DECISIONS.md](docs/DECISIONS.md) : **seul ce qui y est écrit est décidé**. Décisions PD, constats N, questions ouvertes Q.
5. [docs/INTEGRATION_PLAN.md](docs/INTEGRATION_PLAN.md) : phases P0 à P10, tableau de suivi, prochaine action.
6. Selon la tâche : [docs/alternatives.md](docs/alternatives.md) (pourquoi pas un simple seuil), [docs/metrics.md](docs/metrics.md), [docs/constraints.md](docs/constraints.md), [docs/feasibility.md](docs/feasibility.md), [diagram/](diagram/).

## 2. Organisation du dépôt

| Chemin | Contenu |
|---|---|
| `packages/privasoc/` | SOC local : collecte, parseurs, détection, triage, banc d'évaluation (paquet `privasoc`, CLI `privasoc`) |
| `packages/gateway/` | passerelle de sortie sovgate (paquet `sovereign-llm-gateway`, module `sovgate`) |
| `integration/` | tests de contrat entre les deux paquets |
| `deploy/` | composition Docker (privasoc, Vector, modèle local, passerelle en option) |
| `docs/`, `diagram/` | conception, décisions, plan, avancement, diagrammes |

- Workspace uv : un `pyproject.toml` et un `uv.lock` à la racine. `uv sync --all-packages` installe les deux paquets en mode éditable.
- Les anciens dépôts `privasoc` et `sovereign-llm-gateway` sont arrêtés : ne plus y travailler.
- `packages/privasoc/docs/DECISIONS.md` est figé (historique D1 à D62, I1 à I48, toujours citables). Toute nouvelle décision va dans `docs/DECISIONS.md` à la racine.
- L'état local de privasoc (`packages/privasoc/.env`, `data/`, `vector/pipeline.yaml`) contient des secrets et des logs réels : ignoré par git, ne jamais le committer ni le lire sans besoin.

## 3. À la fin de chaque étape ou changement significatif

- Ajouter les décisions et constats dans `docs/DECISIONS.md` : même format de tableau, prochain identifiant libre (PD, N ou Q). **Ne jamais réécrire** une entrée passée : la barrer (`~~...~~`) et renvoyer à sa remplaçante.
- Mettre à jour la colonne **Statut** du tableau de suivi et la section « Prochaine action » de `docs/INTEGRATION_PLAN.md`.
- Mettre à jour `docs/PROGRESS.md` (fait, branches et commits, vérification, prochaines actions) et la section « État actuel » de `README.md`.
- Vérifier avant de committer :
  ```bash
  uv sync --all-packages
  uv run ruff check .
  (cd packages/privasoc && uv run ruff check . && uv run ruff format --check src tests && uv run pytest -q)
  (cd packages/gateway && uv run ruff check . && uv run pytest -q)
  uv run pytest -q integration
  gitleaks protect --staged --redact
  ```
  Les tests de privasoc qui demandent Vector sont ignorés sans le binaire (`PRIVASOC_VECTOR_BIN`).
- Commits : identité « no-reply », sans ligne « Co-Authored-By » ni lien de session.
- Si l'architecture change, mettre à jour `diagram/architecture-v2.mmd` (ou créer une v3) et ses notes ; vérifier que le Mermaid se rend.

## 4. Règles

1. **Vie privée d'abord** : rien n'atteint un modèle externe sans pseudonymisation privasoc et vérification sovgate ; ne jamais affaiblir le garde-fou de fuite (I10) ; la passe de pseudonymisation apprise reste locale (D49, PD20) ; pas de logs bruts vers l'extérieur par défaut (PD15).
2. **Anonymat** : aucun nom réel, identifiant personnel, adresse IP ou domaine réel, nom de machine ni chemin local, dans le code, les tests, les docs ou les commits (voir N41 pour l'état actuel du dépôt distant). Utiliser des valeurs fictives : `jdoe`, `laptop-01`, `192.168.1.0/24`, `example.org`.
3. **Mesurer avant d'automatiser** : un chiffre n'est publié qu'avec son protocole ; le holdout ne sert jamais au réglage ; les seuils et coûts sont fixés dans DECISIONS **avant** la mesure.
4. Les fixtures Elastic (ELv2) sont téléchargées à l'exécution, jamais committées ni citées dans un rapport, et jamais envoyées à un modèle externe (PD19).
5. Style : français pour `docs/`, `diagram/` et les fichiers racine ; anglais dans `packages/` (code, docs des paquets) et les messages de commit ; dates au format AAAA-MM-JJ ; pas de tiret cadratin.
