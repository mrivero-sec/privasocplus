# Instructions pour les assistants IA qui travaillent sur ce dossier

Ce fichier s'adresse à tout assistant (ChatGPT, Codex, Claude...). Ce dossier doit suffire à comprendre le projet et à reprendre le travail.

## 1. Lire dans cet ordre

1. [README.md](README.md) : ce qu'est privasoc+, où on en est, carte des fichiers.
2. [docs/PROGRESS.md](docs/PROGRESS.md) : ce qui est fait, sur quelles branches, comment le vérifier, prochaines actions.
3. [docs/CONTEXT.md](docs/CONTEXT.md) : les deux projets sources (privasoc et sovgate), leurs mécanismes et les identifiants de décision cités.
4. [docs/DECISIONS.md](docs/DECISIONS.md) : **seul ce qui y est écrit est décidé**. Décisions PD, constats N, questions ouvertes Q.
5. [docs/INTEGRATION_PLAN.md](docs/INTEGRATION_PLAN.md) : phases P0 à P10, tableau de suivi, prochaine action.
6. Selon la tâche : [docs/alternatives.md](docs/alternatives.md) (pourquoi pas un simple seuil), [docs/metrics.md](docs/metrics.md), [docs/constraints.md](docs/constraints.md), [docs/feasibility.md](docs/feasibility.md), [diagram/](diagram/).

## 2. Ce qu'est ce dossier

- Un dossier de **conception et de coordination**. Le code se modifie dans les dépôts `privasoc` et `sovereign-llm-gateway` (PD3), qui ne sont pas dans ce dossier.
- Dans ces dépôts, respecter leurs propres règles : `privasoc/AGENTS.md` (lire `docs/DECISIONS.md` du dépôt avant tout changement, tests, gitleaks, anonymat) et la même discipline pour sovgate.

## 3. À la fin de chaque étape ou changement significatif

- Ajouter les décisions et constats dans `docs/DECISIONS.md` : même format de tableau, prochain identifiant libre (PD, N ou Q). **Ne jamais réécrire** une entrée passée : la barrer (`~~...~~`) et renvoyer à sa remplaçante.
- Mettre à jour la colonne **Statut** du tableau de suivi et la section « Prochaine action » de `docs/INTEGRATION_PLAN.md`.
- Mettre à jour `docs/PROGRESS.md` (fait, branches et commits, vérification, prochaines actions) et la section « État actuel » de `README.md`.
- Si une décision de privasoc+ change un dépôt source, créer la décision correspondante dans le journal de ce dépôt (par exemple D58 dans privasoc pour l'escalade automatique) et la citer ici.
- Si l'architecture change, mettre à jour `diagram/architecture-v2.mmd` (ou créer une v3) et ses notes ; vérifier que le Mermaid se rend.

## 4. Règles

1. **Vie privée d'abord** : rien n'atteint un modèle externe sans pseudonymisation privasoc et vérification sovgate ; ne jamais affaiblir le garde-fou de fuite (I10) ; la passe de pseudonymisation apprise reste locale (D49, PD20) ; pas de logs bruts vers l'extérieur par défaut (PD15).
2. **Anonymat** : aucun nom réel, identifiant personnel, adresse IP ou domaine réel, nom de machine ni chemin local, dans ce dossier comme dans les dépôts. Utiliser des valeurs fictives : `jdoe`, `laptop-01`, `192.168.1.0/24`, `example.org`.
3. **Mesurer avant d'automatiser** : un chiffre n'est publié qu'avec son protocole ; le holdout ne sert jamais au réglage ; les seuils et coûts sont fixés dans DECISIONS **avant** la mesure.
4. Les fixtures Elastic (ELv2) ne sont jamais envoyées à un modèle externe (PD19).
5. Style : français dans ce dossier, anglais dans les dépôts ; dates au format AAAA-MM-JJ ; pas de tiret cadratin.
