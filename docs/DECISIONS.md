# privasoc+ : journal des décisions

Journal vivant. Seul ce qui est écrit ici est décidé. Les identifiants sont stables ; une décision remplacée est barrée et renvoie à sa remplaçante, elle n'est jamais réécrite.

- **PD** : décisions de privasoc+.
- **N** : constats et notes d'implémentation (ce qui a été mesuré ou observé dans le code, et ce qui a été fait).
- Les identifiants **D** et **I** sans préfixe renvoient au journal du dépôt `privasoc` (`docs/DECISIONS.md`), résumé dans [CONTEXT.md](CONTEXT.md).

Statuts : **retenu** (décidé), **retenu, à valider** (décidé mais conditionné à une mesure de P0 ou d'une phase), **ouvert** (pas encore tranché).

Sessions de conception : 2026-10-07 (analyse initiale par quatre analyses parallèles, puis révision de l'architecture).

## Objectif

| ID | Décision | Statut |
|---|---|---|
| PD1 | privasoc+ fusionne `privasoc` (SOC local, triage par LLM local) et `sovereign-llm-gateway` (sovgate, passerelle de sortie qui pseudonymise, vérifie et audite) pour qu'une alerte que le modèle local traite mal puisse recevoir un second avis d'un modèle frontière, sans que des données personnelles en clair ne sortent. | retenu |
| PD2 | Même positionnement que les deux projets : outil local d'abord (homelab), qui ne doit pas empêcher un usage SOC / MSSP plus tard ; projets publics et reproductibles par un relecteur sans clé API payante. | retenu |

## Organisation

| ID | Décision | Statut |
|---|---|---|
| ~~PD3~~ | ~~Pas de nouveau dépôt de code. Le code va dans les deux dépôts existants (module `escalate/` dans privasoc, profil « privasoc » dans sovgate) ; ce dossier contient la conception, les décisions, le plan et, à partir de P1, la composition Docker (`deploy/`). Les deux dépôts restent publiables séparément.~~ Remplacé par PD29 (un seul projet). | remplacé |
| PD4 | Langue : ce dossier en français ; le code, les docs et les commits des deux dépôts (aujourd'hui `packages/`, PD29) restent en anglais. Pas de tiret cadratin dans les documents. | retenu |

## Architecture

| ID | Décision | Statut |
|---|---|---|
| ~~PD0~~ | ~~Le modèle local donne un pourcentage de fiabilité sur son verdict ; en dessous de 70 %, sovgate pseudonymise et envoie à un modèle frontière.~~ Remplacé par PD10 à PD16 : la confiance déclarée par un modèle 8B est surconfiante, non calibrée et manipulable par injection ; un seuil ne mesure jamais les erreurs sûres d'elles (voir [alternatives.md](alternatives.md), [metrics.md](metrics.md) section 1). | remplacé |
| ~~PD5~~ | ~~**privasoc pseudonymise, sovgate vérifie.** sovgate n'est pas un second pseudonymiseur des entités de logs : les formes de jetons privasoc sont en liste blanche ; une IP ou une MAC hors des plages de jetons est bloquée (fuite privasoc, transformée en proposition de règle apprise, D33) ; seuls les noms résiduels en texte libre trouvés par GLiNER peuvent être tokenisés par sovgate. Raison : la double pseudonymisation casse la forme et la ré-identification (I33, constats N1 et N2).~~ Remplacée par PD24. | remplacé |
| ~~PD6~~ | ~~sovgate est le **point de sortie unique** de privasoc vers l'extérieur : l'URL distante de privasoc pointe vers une instance sovgate dédiée, sur loopback, authentifiée, avec le profil `policy.privasoc.yaml`. La clé du fournisseur n'existe que dans sovgate.~~ Remplacée par PD25. | remplacé |
| PD7 | Escalade automatique **optionnelle et désactivée par défaut**. Dans privasoc, cela demande une nouvelle décision ~~D57~~ D58 (constat N24) qui amende D53 (« distant seulement sur action humaine »). | retenu |
| PD8 | **Repli sûr** : passerelle indisponible, blocage, budget épuisé, fuite détectée ou réponse invalide donnent toujours « verdict local conservé et alerte en file de revue humaine, raison affichée ». Jamais de clôture silencieuse. | retenu |
| PD9 | Les preuves sont traitées comme **non fiables** (champs contrôlés par l'attaquant) sur les deux chemins : enveloppe `<document>` échappée aussi pour le modèle local, spotlighting de sovgate pour l'externe, injection signalée = revue humaine. | retenu |

## Routage

| ID | Décision | Statut |
|---|---|---|
| PD10 | **Enrichir avant d'escalader** : contexte local (historique de l'hôte, alertes passées de la règle et leurs clôtures, inventaire des actifs, correspondances IOC locales calculées sur les valeurs réelles et transmises comme indicateurs) puis relance du triage local. | retenu |
| PD11 | **Déclencheurs** : règles d'enjeu, désaccord entre deux modèles locaux de familles différentes, affirmations vérifiables fausses, échecs de validation existants (citations, ATT&CK, valeurs inventées), 
eeds_more_info` persistant. La confiance déclarée et l'auto-cohérence restent des signaux secondaires. | retenu, à valider (AUROC des signaux en P3) |
| PD12 | Aucune automatisation du routage avant le **banc de triage** (étape 8 de privasoc) ; go / no-go de l'escalade externe selon le gain mesuré du modèle frontière sur le holdout. | retenu |
| PD13 | **Trois destinations** : local, frontière, analyste. L'analyste est la destination par défaut des cas à fort enjeu. | retenu |
| PD14 | **Politique de routage v1** à règles lisibles (ordre dans [INTEGRATION_PLAN.md](INTEGRATION_PLAN.md) P4) : enjeu élevé et verdict négatif = analyste obligatoire ; le modèle frontière n'abaisse jamais seul un verdict ou une sévérité ; budget d'escalade plafonné (20 % sur 7 jours glissants par défaut), surplus vers l'analyste. Remplace le « seuil de 70 % » et adapte la règle v1 de metrics.md section 6 (le désaccord entre deux modèles remplace l'accord 2/5 d'un seul modèle ; les affirmations fausses s'ajoutent). | retenu, à valider (P4) |
| PD15 | **Charge utile = fiche de faits** déterministe et versionnée (comptes, séquence relative, ports, résultats, jetons, indicateurs), sans chaînes libres contrôlées par l'attaquant par défaut. Les preuves pseudonymisées complètes ne sont envoyées que si une mesure montre que la fiche ne suffit pas, et par décision explicite. | retenu, à valider (P5) |
| PD16 | **Mesure continue par audit aléatoire** d'une petite part des alertes closes (3 % par défaut) et de tous les désaccords, en lot. | retenu |
| PD17 | **Routage appris** (calibration ou prédiction conforme) seulement quand les conditions de metrics.md section 6 sont réunies ; les règles d'enjeu restent prioritaires. | retenu, à valider (P8) |
| PD18 | **Modèle frontière comme professeur** (règles Sigma, exemples, prompts, éventuellement affinage LoRA du local) sur données synthétiques ou déjà pseudonymisées, hors ligne. Objectif : faire baisser le taux d'escalade. | retenu |

## Vie privée et données

| ID | Décision | Statut |
|---|---|---|
| PD19 | Les fixtures Elastic (licence ELv2) ne sont **jamais** envoyées à un modèle externe, y compris en évaluation ; seules des données synthétiques ou publiques sous licence compatible le sont. | retenu |
| PD20 | La passe de pseudonymisation apprise (D49) reste strictement locale ; `ensure_local` doit refuser une passerelle (constat N3). | retenu |
| PD21 | Avant tout envoi de données réelles d'un tiers : contrat avec le fournisseur, option de non-rétention si disponible, base de transfert, analyse d'impact (voir constraints.md section 2). En homelab, données personnelles du seul opérateur. | retenu |
| PD22 | CI et reproductibilité : faux modèle frontière derrière sovgate pour les tests ; aucun test ne demande de clé API. | retenu |
| PD23 | **Lectures pré-enregistrées du banc de triage** (miroir de D57 dans privasoc, écrites avant tout résultat de modèle) : (1) la confiance déclarée ne sert de signal de routage que si son AUROC pour prédire une erreur atteint 0,65 sur le holdout ; (2) l'escalade vers un modèle distant ne vaut d'être construite (P5 à P9) que si, sur les mêmes preuves pseudonymisées du holdout, `accuracy_all` distant moins local atteint 0,10 avec un intervalle apparié à 95 % au-dessus de 0, sans hausse de `missed_tp` ; (3) avec 16 cas holdout ces lectures sont provisoires, le banc grandit avant toute automatisation. | retenu |

## Questions ouvertes

| ID | Question | Piste |
|---|---|---|
| Q1 | Quel deuxième modèle local, compatible avec la configuration de référence de privasoc (GPU grand public de 8 Go, fenêtre de 8 192 jetons) ? | Mini-banc en P3 entre deux ou trois familles |
| Q2 | Logprobs : utiles en plus du désaccord ? | API native `/api/chat` d'Ollama à tester (constat N11) |
| Q3 | Quels champs libres autoriser dans la fiche de faits, et pour quelles règles ? | Mesure en P5 |
| Q4 | Seuil d'écart d'exactitude acceptable entre fiche et preuves complètes | À fixer dans ce journal **avant** la mesure P5 |
| Q5 | Fournisseur frontière et région (UE, non-rétention) | Avant P5 |
| Q6 | Jetons déterministes : une re-clé par escalade pour limiter la liaison chez le fournisseur ? | Arbitrer avec le coût sur les règles apprises |

## Constats et notes d'implémentation

Les constats N1 à N16 viennent de la lecture du code des deux dépôts avant toute implémentation. À partir de N17 : notes d'implémentation.

| ID | Constat | Conséquence | Phase |
|---|---|---|---|
| N1 | Le détecteur EMAIL de sovgate re-tokenise les e-mails pseudonymisés de privasoc (`u…@d…`). | Ré-identification et génération de parseurs cassées sans allowlist. | P1 |
| N2 | Le détecteur CREDIT_CARD (Luhn) de sovgate prend environ 10 % des horodatages en millisecondes et 18 % des SID pour des cartes ; une seule détection classe la requête « restricted » et la route vers le local sans prévenir. | Escalade annulée silencieusement ; désactiver ces détecteurs dans le profil privasoc. | P1 |
| N3 | `privasoc/pseudo/learn.py:ensure_local` accepte toute adresse privée ou loopback : une passerelle sur le LAN passerait pour « locale » et recevrait la passe résiduelle en clair. | Contournement possible de D49. | P1 |
| N4 | Une valeur de log contenant `</document>` peut sortir de l'enveloppe de spotlighting. | Échapper les balises dans les valeurs. | P1 |
| N5 | `LLMClient.check()` de privasoc appelle `GET /models`, absent de sovgate ; sovgate impose son propre nom de modèle. | Ajouter l'endpoint ; journaliser le modèle réellement utilisé. | P1 |
| N6 | privasoc n'envoie ni `X-Tenant-Id` ni `X-Session-Id`. | Ajouter les en-têtes (tenant `privasoc`, session = identifiant d'alerte). | P1 |
| N7 | sovgate charge une seule policy par processus ; ses clés HMAC sont par tenant, mais les jetons privasoc sont produits avec une seule clé globale. | Instance sovgate dédiée ; garantie par tenant non applicable aux jetons privasoc. | P1 |
| N8 | `triage.validate` transforme une confiance absente en 0.0 sans signaler de problème ; la confiance est écrite avant les raisons et n'est utilisée nulle part. | Ajouter le problème de validation ; ne pas s'appuyer sur ce chiffre. | P3 |
| N9 | La table des alertes n'a pas de `closed_at`. | Temps de clôture non mesurable. | P0 |
| N10 | La vérité terrain n'a que deux classes (`closed_tp`, `closed_fp`) : bénin et faux positif ne se distinguent pas. | Ajouter un motif de clôture. | P0 |
| N11 | L'API native `/api/chat` d'Ollama accepte `logprobs` et `top_logprobs` ; l'endpoint compatible `/v1` les liste comme non supportés. privasoc utilise déjà l'API native en local. Interaction avec la sortie JSON et version installée non testées. | Piste Q2. | P3 |
| N12 | Les preuves de triage sont les 20 événements les plus récents. | Un attaquant peut noyer l'événement malveillant ; échantillonnage anti-dilution à prévoir. | P2 |
| N13 | Le spotlighting de sovgate n'enveloppe que le rôle `tool` et les balises listées ; `strip_tools` n'a pas d'effet sur le triage, qui n'a pas d'outils. | Baliser les preuves ; `on_detect: flag` puis revue humaine côté privasoc. | P1 |
| N14 | Coût estimé d'une escalade avec preuves complètes : 6 000 à 10 000 jetons d'entrée, environ 0,02 à 0,17 USD selon les tarifs consultés le 2026-10-07. La fiche de faits devrait réduire fortement ce volume. | À remesurer en P5. | P5 |
| N15 | Premier livrable de conception (2026-10-07) : diagramme v1 centré sur le seuil (`diagram/diagram.mmd`), analyses de faisabilité, de contraintes et de métriques, audit de confidentialité sans trouvaille identifiante. | Le diagramme v1 et le plan de feasibility.md section 4.2 sont remplacés par `diagram/architecture-v2.mmd` et INTEGRATION_PLAN.md ; les autres analyses restent valables. | |
| N16 | Révision du 2026-10-07 : alternatives au seuil ([alternatives.md](alternatives.md)), décisions PD5 à PD22, plan d'intégration en 11 phases, diagramme v2. | État actuel de la conception. | |
| N17 | **P1 implémenté** (2026-10-07). sovgate v0.3.1 : `allowlist_patterns`, `disabled_patterns`, détecteurs `UNMAPPED_IP` / `UNMAPPED_MAC`, profil `config/policy.privasoc.yaml`, `GET /v1/models`, en-têtes `X-Sovgate-Version` et `X-Sovgate-Injection`, types d'entités dans les 403, clés API avec tenant dérivé (`SOVGATE_API_KEYS`). privasoc (I40) : en-têtes tenant / session, `GatewayRefused`, décisions de la passerelle conservées, injection signalée en problème de triage, enveloppe `<document>` échappée pour tous les modèles, `ensure_local` qui refuse une passerelle. Corrige N1 à N7 et N13. 4 tests de contrat dans `integration/`. | Voir PROGRESS.md pour branches et commits. | P1 |
| N18 | « Inspect-then-send » abandonné : le refus de sovgate a lieu avant tout appel amont et renvoie déjà les types et comptes d'entités, donc un appel `/v1/inspect` préalable doublerait la détection pour rien. | Reste à faire : transformer un refus `UNMAPPED_*` en proposition de règle apprise (D33). | P1, plus tard |
| N19 | La composition `deploy/docker-compose.yml` est écrite mais n'a pas été lancée : pas de Docker dans l'environnement de construction. | À lancer une fois sur la machine cible. | P1 |
| N20 | gitleaks signale le secret HMAC de test de sovgate (`generic-api-key`) dans le nouveau fichier de test ; marqué `# gitleaks:allow`. | Faux positif, valeur de test. | |
| N21 | Les trois premiers commits de sovgate ont pour auteur une adresse e-mail personnelle, et non l'identité « no-reply » utilisée par privasoc. Contredit l'anonymat (D43 de privasoc, AGENTS.md règle 2). Les nouveaux commits utilisent l'identité « no-reply ». | Décision du propriétaire : réécrire l'historique de sovgate avant toute mise en avant publique. | |
| N22 | **P0 commencé** : une alerte clôturée garde `closed_at` et `close_reason` (`true_positive`, `false_positive`, `benign`, ce dernier en `closed_fp`), migration automatique, CLI `alerts close <id> benign`, bouton UI (privasoc I41). Corrige N9 et N10. | Le banc de triage reste à faire. | P0 |
| N23 | Environnement de construction : tests lancés dans une VM Linux, environnements virtuels hors des dépôts (`UV_PROJECT_ENVIRONMENT`), sans toucher au `.venv` Windows de privasoc ; Vector absent, d'où 29 tests ignorés dans privasoc. Les commits n'ont pas les lignes « Co-Authored-By » ni de lien de session (I36 de privasoc). | | |
| N24 | Le numéro D57 de privasoc est pris par le protocole de mesure du triage (écrit avant les résultats, voir PD23). L'escalade automatique optionnelle annoncée en PD7 sera **D58**. Les mentions de D57 dans `feasibility.md` (analyse initiale) désignent cette future D58. | | P4 |
| N25 | **Banc de triage livré** (privasoc D57, I42) : 16 familles (8 dev, 8 holdout ; par split 4 vrais positifs, 2 bénins, 2 faux positifs), 2 variantes, 6 jumeaux d'injection, 38 cas ; la détection réelle doit lever exactement l'alerte attendue (le banc se vérifie lui-même). `privasoc eval triage` (local, distant, ligne de base `always-tp`), `privasoc eval triage-report` (avec comparaison appariée `--compare`). Seule la ligne de base est mesurée : le modèle local n'est pas joignable depuis l'environnement de construction. | Lancer le modèle local sur la machine GPU. | P0 |
| N26 | Le banc a révélé deux bogues de pseudonymisation de privasoc, corrigés : la propagation réécrivait les jetons existants (un utilisateur nommé `user` corrompait tous les `user-xxxxxx`) ; la clé `source.ip` du détail d'alerte devenait un jeton de domaine. Fuite mesurée sur les fixtures Elastic inchangée (163 / 2 010). | | P0 |
| N27 | Limites mesurables révélées par le banc : (a) les preuves ne contiennent que les événements qui ont déclenché la règle (pas le login réussi après une force brute) ; (b) noms de domaine et d'utilisateur sont tokenisés étiquette par étiquette, donc le modèle ne voit ni longueur, ni alphabet, ni mots dans les familles DNS, et une injection écrite dans un nom d'utilisateur ou une étiquette DNS ne l'atteint jamais (seuls user-agent et chemins d'URL la portent) ; (c) les plages de documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) sont privées pour Python, donc mappées dans 10/8 : un attaquant « externe » écrit avec elles paraît interne. | (a) relève de P2 (contexte local), (b) de P5 (caractéristiques dérivées dans la fiche de faits : longueur, entropie, alphabet, calculées localement). | P2, P5 |

## Revue et corrections du 2026-10-07

| ID | Décision | Statut |
|---|---|---|
| PD24 | Remplace PD5 pour la vérification des adresses : privasoc reste le pseudonymiseur et sovgate le vérificateur. Le profil strict exige l'authentification et un manifeste des seuls jetons IP/MAC issus du coffre et présents dans la requête. Toute adresse non déclarée est bloquée, même dans une plage de jetons ou avec un préfixe MAC `02`. Le manifeste est borné, retiré avant l'amont et absent de l'audit. Les noms résiduels utilisent le NER ; les collisions avec des jetons existants et les quasi-identifiants restent des limites. Correspondance : privasoc D60/I43, sovgate SG1/SG3. | retenu |
| PD25 | Remplace PD6 pour le déploiement : composition locale par défaut, activation du distant par profil et variante explicites. privasoc n'a que des réseaux internes ; ingestion, modèle local et passerelle sont séparés. Seul sovgate possède le réseau fournisseur et la clé fournisseur. Le serveur Ollama interne a un réseau distinct pour télécharger ses poids et reste de confiance. Ports d'interface et de syslog sur loopback par défaut. NER activé dans la variante distante, échec au démarrage si indisponible. Correspondance : sovgate SG2. | retenu, validation Docker restante |
| PD26 | Précise PD14 : injection, fuite, indisponibilité et budget épuisé passent avant le traitement d'une sortie invalide. Sur une alerte à enjeu élevé, verdict négatif, abstention ou sortie invalide imposent l'analyste. L'enjeu provient du niveau de la règle et de l'inventaire locaux, jamais d'une sévérité abaissée par le modèle. L'avis distant facultatif ne retarde pas la revue obligatoire. | retenu, implémentation P4 restante |
| PD27 | Corrige la méthode d'intervalle de PD23 sans changer ses seuils : bootstrap par familles de scénarios, 2 000 tirages, variantes et répétitions groupées ; comparaison appariée refusée si cas ou runs manquent, si doublons ou métadonnées incohérentes. Aucun intervalle avec moins de deux familles. La correction est faite avant toute mesure de modèle. Correspondance : privasoc D59/I43, correction explicite de D57. | retenu |
| PD28 | Précise PD16 : l'échantillon aléatoire des alertes closes et les désaccords sont distingués, ou pondérés selon leur inclusion. L'estimation porte sur les alertes closes, pas sur toutes les alertes. Un avis frontière ne vaut pas vérité terrain ; adjudication humaine indépendante requise pour mesurer une erreur. | retenu, P7 restant |

| ID | Constat | Conséquence | Phase |
|---|---|---|---|
| N28 | Revue du contrat : la seule forme d'un jeton ne prouvait pas sa pseudonymisation ; NER désactivé dans le profil de test ; variantes du banc corrélées ; priorité de routage ambiguë ; composition sans segmentation et syslog ouvert par défaut. Corrections : D59/D60/I43, SG1 à SG3 et PD24 à PD28. | Ne pas présenter P1 comme terminé opérationnellement ni promettre zéro fuite universel. | P0, P1, P4 |
| N29 | Tests de la revue : contrat réel entre dépôts avec amont simulé, dont quatre adresses oubliées ayant la forme de jetons ; régression sur les familles statistiques et les paires incomplètes ; refus des alias DNS du distant ; manifeste absent de l'amont et de l'audit ; refus du mode fail-open et d'un NER indisponible. Résultats exacts dans PROGRESS. | Les modèles réels et GLiNER réel ne sont pas évalués par ces tests. | P0, P1 |
| N30 | La composition de revue définit un serveur Ollama interne, des réseaux séparés, le distant explicitement activé et un NER obligatoire en déploiement. Docker n'est pas démarré dans l'environnement de revue. | Vérifier le démarrage, l'ingestion, le réseau, les poids et le repli sur la machine cible ; configuration syntaxique seule insuffisante. | P1 |
| N31 | Vérifications finales de la revue : privasoc 173 tests passants, 29 ignorés sans Vector ; sovgate 89 passants ; 8 contrats inter-dépôts et 3 contrôles Compose passants ; Ruff et Gitleaks passent avec les seules exceptions synthétiques précises de SG4. Diagramme v3 rendu et vérifié. Commits locaux `945ae9c` / `d2c81db`. | Aucun bénéfice de modèle distant ni aucune garantie universelle de confidentialité n'est déduit de ces tests. | P0, P1 |
| N32 | Lancement natif local du 2026-10-07 : `/health` répond 200 ; connexion du tableau de bord avec le jeton existant, page Dashboard effectivement observée ; Vector existant démarre, écoute TCP/UDP 5514 sur loopback et utilise le sink local ; Ollama `/api/tags` confirme `qwen3:8b`. Clés et données existantes conservées, distant et repli automatique désactivés. Docker Desktop échoue à l'initialisation du gestionnaire d'inférence sur un socket temporaire de zéro octet ; Windows refuse aussi sa suppression. | L'interface et la collecte fonctionnent sans Docker. La composition, le NER réel et la qualité de triage restent à valider. Le lancement utilise l'exécutable CLI `privasoc serve`, pas `python -m privasoc`. | P1 |
| N33 | Samples publics pour test d’ingestion, autorisation de l’opérateur le 2026-10-07 : trois extraits Loghub de 2 000 lignes et quatre fixtures Elastic du dev (pas du holdout), commits amont figés, licences et manifeste SHA-256 conservés dans `privasoc/data/samples-manual/2026-10-07/`. Dossier explicitement ignoré et hors de `data/inbox/`. Import automatique effectué une seule fois : 6 111 lignes au total, 13 normalisées et 6 098 en quarantaine. Six générations de parseur local `qwen3:8b`, mode structuré, deux tentatives maximum : six 
eeds_escalation`, aucun nouveau parseur activé. Aucune alerte pour ces sources lors du contrôle ; aucun appel externe. Correspondance : privasoc I45. | Protocole, comptes et sources dans MANUAL_SAMPLES ; ce corpus non étiqueté ne remplace pas le jeu public du banc P0. Ne pas réimporter les mêmes fichiers sans traiter les doublons. | Test opérationnel, hors banc P0 |
| N34 | Vérifications de la préparation des samples : fichiers et notices ignorés, aucun suivi Git des données ; suite source 173 passants et 29 ignorés ; Ruff et Gitleaks sur l’index passent. Commit local `28edc2e` limité au `.gitignore`, README et journal source. | Les données, licences copiées et rapports détaillés restent exclusivement locaux dans `data/`. | |
| N35 | Audit statique Codex Security du dossier privasoc+ le 2026-10-07, scan `b0283784-124e-4034-aaa6-cdc5283580c7` : revue indépendante générale, architecture et investigation du déploiement ; aucune vulnérabilité étayée dans le contenu examiné. Aucun test exécuté, aucun conteneur démarré, aucun appel fournisseur. Sources applicatives des deux dépôts hors périmètre ; PNG dérivés et caches exclus. Le résolveur SECURITY.md échoue sur le chemin Windows, aucun SECURITY.md trouvé dans la cible par inventaire direct. | Rapport et couverture conservés dans le workbench Codex Security. Couverture opérationnelle partielle : auditer séparément les deux dépôts et valider Docker, NER réel, refus de sortie directe et conservation du triage lors d'une panne. L'absence de secret fournisseur dans le fichier d'environnement source reste une obligation de l'opérateur. | P1 |

| ID | Question | Piste |
|---|---|---|
| Q7 | Quel plafond absolu de coût et d'appels, en plus du plafond relatif de 20 % ? | Fixer dans ce journal avant P4 ; un pourcentage seul ne borne pas le coût lors d'une hausse de volume. |
| Q8 | Quels coûts d'erreur et de revue humaine utiliser pour valider P4 ? | Les chiffres de metrics restent hypothétiques ; les décider avant la mesure, ainsi que le volume acceptable de la file analyste. |

| N36 | Correction du parsing des samples (2026-10-07), privasoc D61/I46 : deux parseurs fixes Apache et erreurs YAML précises. Rattrapage sans nouvel import : 2 017 lignes supplémentaires, total 2 030 événements et 4 081 lignes en quarantaine. Quatre nouvelles générations locales, cinq tentatives maximum : Linux 93602e98 proposé ; SSH, iptables et Check Point restent bloqués. Contrôle Linux séparé sur 100 lignes réelles : compilation, ECS et ancrage passants, mais extraction surtout de l’en-tête et du message. Aucun parseur généré activé, aucun appel externe. | Revue explicite D23 avant activation Linux ; couverture de formes distincte de l’exactitude d’extraction ou de détection. | Test opérationnel |

| N37 | Vérification N36 : 205 tests privasoc passants avec Vector natif, aucun ignoré ; Ruff et Gitleaks historique/index passants ; santé API et page de revue Linux authentifiée HTTP 200 après redémarrage local. Sept alertes de santé de sources, zéro alerte Sigma pour le corpus. Commit local `da0351d`, non poussé (privasoc I47). | Linux reste proposé en attente de décision explicite D23. | Test opérationnel |

| N38 | À la demande de l’opérateur, Linux reste en revue avec extraction enrichie, privasoc D62/I48. Candidat manuel 90198064, exemple structuré réutilisable, pas de routage automatique : 2 000 lignes vérifiées localement, 2 000 sorties, validation ECS et ancrage passants. Processus 2000, PID 1849, IP source 1211, utilisateur 620, résultat 609, corps non classés 236. | Comptes de présence, pas exactitude des champs ; messages inconnus sans verdict inventé. Année courante inférée pour les horodatages sans année. Aucun import ni activation supplémentaire. | Test opérationnel |

| N39 | Validation finale N38 : suite complète 206 tests passants avec Vector, régression ciblée passante après dernière variante ; Ruff et Gitleaks historique/index passants. Commit local `257c7b8`, non poussé. Page de revue du candidat 90198064 HTTP 200, état proposed confirmé ; les 2 000 lignes Linux restent en quarantaine conformément au choix de l’opérateur. | La suite du test attend une revue de qualité, sans nouvelle demande d’activation automatique. | Test opérationnel |

## Un seul projet (2026-10-07)

| ID | Décision | Statut |
|---|---|---|
| PD29 | **privasoc+ est le seul projet.** Remplace PD3. Les dépôts `privasoc` et `sovereign-llm-gateway` sont arrêtés et figés (une note de déménagement dans leur README, rien d'autre). Leur code vit ici dans un monorepo, workspace uv à deux paquets : `packages/privasoc` (SOC local) et `packages/gateway` (passerelle sovgate), un seul `uv.lock` racine, une seule CI, ce journal comme **unique** journal de décisions (ceux des paquets sont figés et servent d'historique : D1 à D62, I1 à I48 de privasoc restent citables). Historique git neuf : le code arrive par un commit d'import, sans les historiques des anciens dépôts (adresse e-mail personnelle dans les premiers commits de sovgate N21, traces de session I36 de privasoc). Fusion en un seul paquet Python possible plus tard, non décidée. | retenu |

| ID | Constat | Conséquence | Phase |
|---|---|---|---|
| N40 | Import fait depuis les branches `privasoc-plus` (privasoc `257c7b8`, sovgate `d2c81db`), fichiers suivis seulement. Retirés à l'import : CI, `docker-compose.yml`, `AGENTS.md` et `uv.lock` propres aux paquets (remplacés par ceux de la racine), `LICENSE` des paquets (une seule à la racine, titulaire « privasoc+ contributors » ; celle de sovgate portait un nom réel), `.gitleaksignore` de sovgate (empreintes de l'ancien historique). L'état local non suivi de privasoc (`.env`, `data/` avec coffre et base, `vector/pipeline.yaml`, `docs/*.fr.md`) est copié dans `packages/privasoc/`, toujours ignoré par git ; les anciens dossiers gardent leur copie. Dockerfile de privasoc construit depuis la racine (`docker build -f packages/privasoc/Dockerfile .`, `uv sync --frozen --package privasoc` vérifié hors Docker) ; `deploy/` pointe vers `../packages/...`. Vérifications : privasoc 174 passants et 32 ignorés sans Vector (206 attendus avec Vector, N39), gateway 89 passants, contrat 8 passants et 3 ignorés sans Docker, Ruff et Gitleaks passants. | Lancer la suite privasoc avec Vector sur la machine Windows depuis `packages/privasoc`. | |
| N41 | Anonymat (AGENTS règle 2) : le dépôt distant de privasoc+ est sous un compte dont le nom évoque le nom réel de l'opérateur, et ses deux premiers commits ont une adresse e-mail personnelle comme auteur. Les commits de l'import utilisent l'identité « no-reply ». | Décision de l'opérateur : garder l'anonymat (nouveau compte ou dépôt, réécriture des deux commits) ou l'abandonner (alors amender la règle 2 et D43). Rien n'est poussé tant que ce n'est pas tranché. | |
| N42 | Le monorepo (commit `cb57e55`) a été poussé par l'opérateur le 2026-10-07 sur le dépôt distant existant, sous le compte nominatif signalé en N41 ; les deux premiers commits gardent l'adresse personnelle. README racine réécrit comme page d'accueil publique (état, architecture, démarrage, documentation, limites), les notes de session restant dans PROGRESS et ce journal. | N41 devient : amender ou non la règle d'anonymat (AGENTS règle 2, D43), le dépôt n'étant plus anonyme de fait. | |
