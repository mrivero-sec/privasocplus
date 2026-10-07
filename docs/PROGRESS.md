# privasoc+ : journal d'avancement

Fichier de reprise. Un agent qui reprend le travail lit d'abord [AGENTS.md](../AGENTS.md), puis ce fichier. Mettre à jour à la fin de chaque session : ce qui est fait, où, comment le vérifier, et la suite.

## État au 2026-10-07 (revue 3, puis import dans un seul dépôt)

Audit statique Codex Security du dossier terminé (N35), sans vulnérabilité étayée dans le contenu examiné. La couverture opérationnelle reste partielle et les deux dépôts sources sont hors périmètre.

| Phase | Statut |
|---|---|
| P0 Banc de triage | **banc livré** : clôture, harnais et protocole livrés ; intervalles corrigés par familles (D59) ; aucune mesure de modèle, jeu public restant |
| P1 Sécurité et tuyauterie | **implémenté, tests simulés passants** ; validation opérationnelle Docker et NER réel restante |
| P2 à P10 | à faire |

Le triage distant reste une action humaine (D53 de privasoc) : rien n'escalade automatiquement avant P4.

## Où est le code

**Un seul dépôt** (PD29) : ce dossier, branche `main`. Le code des deux anciens dépôts y a été importé le 2026-10-07 avec un historique git neuf (N40) :

| Chemin | Origine | Dernier commit importé |
|---|---|---|
| `packages/privasoc` | ancien dépôt `privasoc`, branche `privasoc-plus` | `257c7b8` |
| `packages/gateway` | ancien dépôt `sovereign-llm-gateway`, branche `privasoc-plus` | `d2c81db` |

Les hashes cités plus bas (`bdaad37`, `945ae9c`, `a67fad3`...) désignent des commits des anciens dépôts, qui restent consultables là-bas mais ne reçoivent plus rien. Poussé par l'opérateur le 2026-10-07 sur le dépôt distant `privasocplus` (N42).

## Ce qui a été fait

### P1, sovgate (`sovereign-llm-gateway`, v0.3.1)

- `src/sovgate/config.py` : `VerifierConfig` (`unmapped_ip`, `ip_allow`, `unmapped_mac`, `mac_allow_prefixes`), champs de policy `disabled_patterns`, `allowlist_patterns`, `verifier` ; `Settings.api_keys` lu depuis `SOVGATE_API_KEYS=key:tenant,...`.
- `src/sovgate/pii/detectors.py` : `UnmappedAddressDetector` (IPv4, IPv6, MAC hors plages autorisées).
- `src/sovgate/pii/factory.py` : désactivation de motifs, ajout du vérificateur ; un motif inconnu est refusé.
- `src/sovgate/pipeline.py` : `_drop_allowlisted` retire les spans entièrement contenus dans un jeton client, avant et après la propagation des noms.
- `src/sovgate/app.py` : `GET /v1/models`, en-tête `X-Sovgate-Version` sur toutes les réponses, `X-Sovgate-Injection` si le scan signale, 403 avec types et comptes d'entités (jamais de valeurs), tenant dérivé de la clé quand des clés sont configurées.
- `config/policy.privasoc.yaml` : le profil (jetons privasoc en liste blanche, `UNMAPPED_*` restricted, `restricted: block`, CREDIT_CARD / PHONE_CH / AHV désactivés, `pseudonym_scope: session`, `on_detect: flag`, balise `document` non fiable).
- `tests/test_privasoc_profile.py` : 13 tests. Docs : README (section « Clients that pseudonymise on their own side »), ROADMAP (v0.3.1), `.env.example`.
- Comportement de la policy par défaut inchangé (test dédié).

### P1, privasoc (I40)

- `src/privasoc/llm.py` : `Endpoint.headers`, `LLMClient.gateway` (rempli par `check()` si `X-Sovgate-Version`), `GatewayRefused` sur 403 / 502 / 503 d'une passerelle (journalisé sans contenu), `Reply.gateway` (action, upstream, request-id, injection) conservé dans le journal d'appels.
- `src/privasoc/detect/triage.py` : preuves (émetteur, détail d'alerte, événements) dans `<document>` pour tous les modèles, séquences de balises échappées (`&lt;/document`), consigne système sur le contenu non fiable, injection signalée par la passerelle ajoutée aux `problems`, `gateway` dans l'enregistrement de triage.
- `src/privasoc/pseudo/learn.py` : `ensure_local(url, not_like=...)` refuse l'hôte:port de l'URL distante ; `residual_pass` refuse un client qui a reconnu une passerelle.
- `src/privasoc/service.py` : `_endpoint(..., session=)` avec `X-Tenant-Id` (`PRIVASOC_LLM_REMOTE_TENANT`) et `X-Session-Id` (`alert-<id>` ou aléatoire, jamais une valeur réelle) ; `GatewayRefused` converti en message clair (triage existant conservé) dans le triage et la génération de parseurs ; `_local_llm` refuse une passerelle.
- `src/privasoc/config.py`, `.env.example` : `llm_remote_tenant`.
- `tests/test_gateway.py` : 5 tests. Docs : DECISIONS I40, README (modèle de confidentialité), HANDOFF.fr.md.

### P1, ce dossier

- `integration/test_p1_contract.py` + `integration/README.md` : 8 tests de contrat après la revue 3 avec le vrai code des deux dépôts et un faux modèle frontière (jetons intacts, rien d'original ne sort, IP manquée bloquée, injection signalée, passe locale qui refuse la passerelle).
- `deploy/docker-compose.yml` + `deploy/.env.example` : privasoc, Vector et sovgate ; sovgate sans port publié, clé fournisseur seulement dans sovgate. Revue 3 : réseaux internes séparés, serveur Ollama interne, distant activé explicitement, NER actif dans le déploiement. **Pas encore lancé** (N19).

### P0, privasoc (I41)

- `store.py` : colonnes `closed_at`, `close_reason` sur `alerts`, migration automatique.
- `detect/alerts.py` : `REASONS`, `set_status(store, aid, status, reason=None)` (raison par défaut, raison incohérente refusée, réouverture qui efface).
- `service.py`, `cli.py` (`alerts close <id> tp|fp|benign`), `web/__init__.py` et `alert.html` (bouton « Close: benign », badge du motif).
- `tests/test_closure.py` : 5 tests. Docs : DECISIONS I41, README, HANDOFF.fr.md.

### P0, privasoc : banc de triage (D57, I42)

- `src/privasoc/bench_triage.py` : 16 familles de scénarios (règles SSH, scan de ports, scan web, DNS long), 8 dev et 8 holdout, 2 variantes chacune, 6 jumeaux d'injection, 38 cas. Vérité : `true_positive`, `benign`, `false_positive`. Deux familles marquées `needs_context` (scanner autorisé, antivirus DNS). `load()` fait passer les événements par la vraie détection (règles privasoc seulement) et lève une erreur si un cas ne déclenche pas exactement son alerte.
- `src/privasoc/eval_triage.py` : `run()` (reprise possible, une ligne JSONL par cas, modèle et run), `AlwaysTruePositive` (ligne de base), `summarise()` (accuracy avec abstention, rappel TP, TP manqués, rappel des négatifs, label exact, ECE, Brier, AUROC, injection, intervalles bootstrap), `compare()` (comparaison appariée pour le go / no-go), `report()`.
- CLI : `privasoc eval triage --set dev|holdout|all --provider local|remote|always-tp --runs 3`, `privasoc eval triage-report [--compare a,b]`.
- Résultats : `evaluation/results-triage.jsonl` et `reports/triage.md` avec la ligne de base seulement (accuracy 0,5 ; rappel TP 1 ; rappel des négatifs 0).
- Protocole et seuils écrits **avant** tout résultat : D57 dans privasoc, PD23 ici.
- Bogues corrigés en chemin (commit séparé) : propagation qui réécrivait les jetons, clé `source.ip` du détail d'alerte tokenisée. Fuite sur les fixtures Elastic inchangée (163 / 2 010).
- Limites révélées (N27) : preuves limitées aux événements qui ont déclenché la règle ; domaines et noms d'utilisateur tokenisés (DNS illisible pour le modèle, injection neutralisée dans ces champs) ; plages de documentation mappées en privé.
- `tests/test_bench_triage.py` : 9 tests.

## Comment vérifier

Depuis la racine (workspace uv, PD29) :

```bash
uv sync --all-packages
uv run ruff check .
(cd packages/privasoc && uv run ruff check . && uv run ruff format --check src tests && uv run pytest -q)
(cd packages/gateway && uv run ruff check . && uv run pytest -q)
uv run pytest -q integration
# 2026-10-07 après l'import, sans Vector ni Docker : privasoc 174 passants, 32 ignorés ;
# gateway 89 passants ; contrat 8 passants, 3 ignorés. Avec Vector : 206 privasoc (N39).
```

Ancienne procédure, avant l'import (pour mémoire) :

Environnements virtuels **hors des dépôts** (ne pas toucher au `.venv` existant de privasoc, créé sous Windows) :

```bash
# privasoc
cd privasoc && UV_PROJECT_ENVIRONMENT=~/venvs/privasoc uv sync && \
  UV_PROJECT_ENVIRONMENT=~/venvs/privasoc uv run --frozen pytest -q -p no:cacheprovider && \
  UV_PROJECT_ENVIRONMENT=~/venvs/privasoc uv run --frozen ruff check .
# revue 3 : 173 passed, 29 skipped (sans binaire Vector)

# sovgate
python3 -m venv ~/venvs/sovgate && ~/venvs/sovgate/bin/pip install -e ".[dev]"
~/venvs/sovgate/bin/pytest -q -p no:cacheprovider && ~/venvs/sovgate/bin/ruff check .
# revue 3 : 89 passed

# contrat entre les deux : voir integration/README.md
# revue 3 : 8 tests de contrat ; 3 contrôles Compose supplémentaires si le client Docker est disponible
```

`gitleaks avec masquage des secrets sur les changements avant chaque commit ; résultats de la revue ci-dessous.

## Pièges connus

- `ruff format --check` signale déjà `README.md` dans sovgate avant nos changements : ne pas reformater ce qui n'a pas été touché.
- Les tests de contrat utilisent les paquets du workspace en mode éditable : plus besoin de réinstaller.
- Commits : identité « no-reply » du dépôt privasoc, sans « Co-Authored-By » ni lien de session (I36 de privasoc).
- La plage 203.0.113.0/24 (documentation) est « privée » pour Python : privasoc la mappe dans 10/8, pas dans 198.18/15.
- Les tests de privasoc et de gateway se lancent depuis le dossier de leur paquet (chemins relatifs dans les tests).
- Fichiers Markdown : UTF-8 et fins de ligne LF (`.gitattributes`). Une édition par PowerShell avait inséré du UTF-16 et transformé des « `n » en retours à la ligne ; corrigé le 2026-10-07.

## Prochaines actions (dans l'ordre)

0. Archiver les deux anciens dépôts sur GitHub. Décider si la règle d'anonymat (AGENTS règle 2) est amendée, le dépôt étant publié sous un compte nominatif (N42). Lancer une fois la suite privasoc avec Vector depuis `packages/privasoc` (206 attendus).

Suivi sécurité N35 : auditer les implémentations des deux paquets (`packages/`). Le rapport du scan `b0283784-124e-4034-aaa6-cdc5283580c7` est conservé dans le workbench Codex Security, avec modèle de menace et couverture. Audit hors ligne par lecture statique, sans nouveaux tests ou appels distants ; aucune branche ni aucun commit source modifié. Docker, NER réel et comportement de panne restent à vérifier.

1. **P0, mesures** (sur la machine qui a le GPU et Ollama ; l'environnement de construction ne joint pas le modèle local) :
   ```bash
   cd packages/privasoc
   uv run privasoc eval triage --set all --runs 3        # ~38 x 3 triages, quelques secondes chacun
   uv run privasoc eval triage-report                    # reports/triage.md
   ```
   Puis lire les résultats contre les seuils pré-enregistrés (D57, PD23) et les consigner dans DECISIONS (nouveau constat N) et ici. Ne pas modifier les prompts en regardant le holdout.
2. **P0, comparaison distante** (décision humaine, D53) : configurer sovgate (`deploy/`) et l'URL distante de privasoc, puis `privasoc eval triage --set holdout --provider remote --runs 3` et `privasoc eval triage-report --compare qwen3:8b,<modèle distant>`. Données synthétiques uniquement, jamais les fixtures Elastic (PD19).
3. **P0, élargir le banc** : un jeu public (AIT-LDS v2, voir `metrics.md` section 5.2) et plus de familles par règle, pour réduire les intervalles (16 cas holdout aujourd'hui).
4. **P1, reste** : suivre `deploy/README.md` pour le démarrage, l’ingestion, les refus, le NER réel et la vérification du réseau ; transformer un refus `UNMAPPED_*` en proposition de règle apprise (N18).
5. Puis P2 (contexte local : événements voisins, historique, inventaire, IOC) et P3 (deux modèles, affirmations vérifiables). N27 donne déjà les cas du banc que P2 et P5 doivent faire progresser.

## Corrections de la revue 3

- privasoc D59/D60/I43 : intervalles par familles, paires complètes ; manifeste des jetons
  IP/MAC issus du coffre, fourni au triage, aux parseurs et aux règles ; refus des alias
  DNS du distant dans la passe locale. D58 reste réservé, aucune escalade automatique.
- sovgate SG1 à SG3 : authentification et manifeste strict, suppression avant l'amont,
  refus des adresses non déclarées, fail-closed obligatoire ; choix du NER et du modèle
  effectif par variables de déploiement. La policy générale est inchangée.
- Composition : trois réseaux internes pour privasoc ; Vector isolé de sovgate et des
  secrets du coffre ; serveur Ollama interne ; syslog loopback ; profil distant + variante
  explicites ; NER installé et activé pour le distant. Docker reste à démarrer sur la cible.
- P4 : obligations humaines prioritaires et enjeu fixé par les données locales. P7 :
  population mesurée et adjudication clarifiées. Ces phases restent à implémenter.
- Diagramme v3 et notes actualisées ; les anciennes versions sont conservées.

### Vérifications de la revue

- privasoc : **173 passed, 29 skipped** ; les tests ignorés requièrent Vector.
- sovgate : **89 passed** ; poids NER et fournisseur simulés dans les tests concernés.
- intégration : **8 tests de contrat + 3 contrôles de configuration Compose passants**.
  La composition locale et la variante distante sont normalisées par le client Docker,
  sans lecture de secret réel et sans démarrer de conteneur.
- Ruff : passe sur les sources, leurs tests et les tests d'intégration.
- Gitleaks 8.30.1 : changements, index avant commit et historiques contrôlés. Deux
  constantes synthétiques historiques de sovgate font l'objet d'exceptions limitées
  à leur empreinte exacte (SG4). Aucune exclusion générale de dossier ou de règle.
- Mermaid v3 : SVG et PNG rendus, lecture du PNG vérifiée.
- Commits locaux : `945ae9c` et `d2c81db`, rien poussé ni fusionné.

Docker n'est pas démarré ici : réseau effectif, ingestion et GLiNER réel restent à
valider. Aucun résultat de modèle local ou de fournisseur externe n'est ajouté.
Les avertissements de dépréciation Starlette/httpx préexistants ne font pas échouer
les suites. La réécriture d'historique liée à N21 reste une décision du propriétaire.

## Lancement local du 2026-10-07 (N32)

- API : `/health` vérifié, réponse 200. Tableau de bord ouvert et connecté dans le
  navigateur, page Dashboard effectivement observée sur `http://127.0.0.1:8000/ui/`.
- Vector 0.55.0 natif : démarrage confirmé, écoute `127.0.0.1:5514` TCP/UDP,
  sink vers l'API locale ; fichiers d'entrée dans `data/inbox/` du dépôt source.
- Ollama existant : `/api/tags` répond et annonce `qwen3:8b`. Pas de mesure de
  qualité ou de latence ajoutée ; la présence du modèle ne vaut pas un triage validé.
- Clés, coffre et base existants conservés. Modèle distant et repli automatique
  désactivés. Les processus API et Vector restent en arrière-plan ; PID et journaux
  sont dans `data/runtime/` du dépôt privasoc, git-ignoré.
- Le bon point d'entrée natif est `.venv/Scripts/privasoc.exe serve`.
  `python -m privasoc` ne fonctionne pas, car le paquet n'a pas de `__main__`.
- `deploy/.env` local créé avec le jeton d'ingestion existant, git-ignoré.
- Docker Desktop a échoué sur le socket temporaire du gestionnaire d'inférence.
  Le fichier est de zéro octet, mais Windows refuse son accès et sa suppression.
  Le moteur Docker n'est pas actif ; aucune réinitialisation d'usine effectuée.
  La composition et GLiNER réel restent à vérifier après réparation sur l'hôte.

Les contrôles de cette étape concernent les services et l'interface en fonctionnement.
Aucun code source n'a changé et aucune nouvelle mesure du banc P0 n'a été produite.

## Test automatique de samples publics (N33)

- Sept fichiers téléchargés à des commits amont figés : trois extraits Loghub
  (SSH, système Linux, erreurs Apache) et quatre fixtures Elastic dev (accès Apache,
  accès Nginx, Check Point, iptables). Provenance, licences et SHA-256 sont conservés
  dans `privasoc/data/samples-manual/2026-10-07/`, hors du dossier surveillé par Vector.
- Le dossier était déjà couvert par `data/*` ; une règle explicite
  `data/samples-manual/` est ajoutée au `.gitignore` source et vérifiée par `git check-ignore`.
- L’opérateur a ensuite autorisé l’import automatique : une seule ingestion par fichier,
  sept sources fictives approuvées. Résultat SQL : 6 111 lignes = 13 événements normalisés
  (Nginx reconnu comme `apache_combined`) + 6 098 lignes en quarantaine. Aucun doublon
  volontairement créé. Les commandes manuelles du guide sont conservées comme documentation.
- Six essais de génération locale sur les formats inconnus : `qwen3:8b`, mode structuré,
  deux tentatives maximum, pas de repli externe. Six `needs_escalation` ; aucun parseur
  généré activé. Les pages Hosts et Parsers ont été vérifiées en session authentifiée (200).
- Détection lancée, aucune alerte pour ces sources au contrôle. L’absence d’alerte ne
  signifie pas que les logs sont bénins : la plupart ne sont pas normalisés.
- Tests du dépôt : 173 passants, 29 ignorés sans Vector dans l’environnement de tests ;
  Ruff passe. Le collecteur natif utilise néanmoins le binaire Vector configuré.
- Guide et protocole : [MANUAL_SAMPLES.md](MANUAL_SAMPLES.md). Ce corpus n’est pas ajouté
  au holdout ou au banc P0 ; il n’a pas de vérité terrain d’attaque. La prochaine action
  est d’examiner les échecs de parsing, puis retester la détection sur les lignes normalisées.
- Contrôle de secrets sur l’index avant commit : passe. Commit local de documentation
  et d’ignorance : `28edc2e`, aucun log, aucune licence copiée et aucun rapport brut committé.

## Reprise parsing des samples (2026-10-07)

N36, privasoc D61/I46 : catalogue fixe Apache étendu et erreurs YAML avec cause,
ligne et colonne. Rattrapage de la quarantaine, sans doublons : 2 030 événements,
4 081 lignes restantes. Quatre générations locales supplémentaires, max cinq
tentatives : Linux 93602e98 proposé, SSH/iptables/Check Point en échec. Linux vérifié
sur 100 lignes réelles, mais principalement en-tête/message ; pas d’activation
sans revue explicite D23. Aucun distant, aucun holdout utilisé.

Suite : revoir le parseur Linux, puis traiter les formes SSH manquantes, les sorties
iptables sans champ ECS et les réponses Check Point. Ce corpus ne clôture pas P0.

Vérification finale N37 : **205 tests passants avec Vector, zéro ignoré**, Ruff et Gitleaks passent. Commit source local `da0351d`, branche `privasoc-plus`, non poussé. API et revue Linux authentifiée répondent 200. Sept alertes de santé, zéro alerte Sigma pour les samples. Proposition Linux non activée ; demande explicite de revue transmise conformément à D23.

## Extraction Linux enrichie à la demande de l’opérateur

N38, D62/I48 : candidat 90198064 conservé en revue, non activé. Exemple Linux structuré
réutilisable, testé sur 2 000 lignes réelles locales et sur des scénarios synthétiques.
Champs processus/PID, IP, utilisateur et résultats d’authentification/session, avec
corps inconnus conservés sans classification. Rapport local ignoré, aucune donnée
brute dans le dépôt. 206 tests passants avec Vector ; régression ciblée passante après
la dernière variante d’en-tête ; Ruff passe. Aucun nouvel import ni appel externe.

Suite : revue de l’extraction Linux, sans activation automatique ; poursuivre
séparément SSH, iptables et Check Point.

Commit local de l’extraction Linux : `257c7b8`, branche `privasoc-plus`, non poussé. Gitleaks historique/index passe ; page de revue HTTP 200, état `proposed` confirmé, les 2 000 lignes restent en quarantaine.
