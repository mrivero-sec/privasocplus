# privasoc+ : étude de faisabilité technique

> Analyse initiale conservée comme historique. Les décisions actuelles de DECISIONS
> priment : PD19 interdit tout envoi des fixtures Elastic ; PD24 impose le manifeste
> des adresses ; PD25 corrige le déploiement ; PD26 fixe les priorités de revue humaine.
> Les constats initiaux ne décrivent pas tous le code corrigé. L’inspect-then-send est
> abandonné (N18) ; D58 reste le numéro prévu pour l’escalade automatique. Voir PROGRESS.


> Note du 2026-10-07 : le plan par phases de la section 4.2 est remplacé par [INTEGRATION_PLAN.md](INTEGRATION_PLAN.md) ; le contrat de la section 2.2 est retenu (DECISIONS PD5). Le reste de l'analyse reste valable.

Objet : fusionner `privasoc` (SOC local, pseudonymisation à forme préservée, triage IA validé) et `sovereign-llm-gateway` (`sovgate`, passerelle d'egress OpenAI-compatible) pour qu'un triage local jugé peu fiable soit escaladé, pseudonymisé, vers un modèle frontière.

Base : lecture du code source fourni. Fichiers non fournis, donc hypothèses : `privasoc/pseudo/detectors.py`, `privasoc/generator.py`, `privasoc/detect/author.py`, `sovgate/pii/ner.py`, `sovgate/pii/factory.py`, `sovgate/pii/vault.py`.

## 0. Verdict en une phrase

Faisable, et la tuyauterie est peu coûteuse (environ 5 à 7 jours pour un MVP). Mais **le seuil "70 % de fiabilité" n'a aujourd'hui aucun sens** : le chiffre `confidence` est auto-déclaré par un modèle 8B et n'est utilisé nulle part. Il n'existe pas non plus de jeu de triage étiqueté pour le calibrer, ni de mesure du gain réel d'un modèle frontière sur des preuves pseudonymisées. Le prérequis bloquant est donc l'étape 8 de privasoc (évaluation du triage). Côté passerelle, sovgate doit servir de **vérificateur et porte de fuite**, pas de second pseudonymiseur : ses détecteurs actuels cassent la forme des jetons privasoc et routent à tort une part notable des alertes vers `local`.

---

## 1. Points d'intégration

### 1.1 Ce que privasoc envoie aujourd'hui (`src/privasoc/llm.py`)

| Élément | Comportement actuel | Conséquence avec sovgate |
|---|---|---|
| `Endpoint("remote", url, model, api_key)` (`service._endpoint`) | URL et modèle depuis `PRIVASOC_LLM_REMOTE_URL/MODEL` | Il suffit de pointer `PRIVASOC_LLM_REMOTE_URL` vers `http://<sovgate>/v1`. **Seul l'endpoint remote** doit passer par sovgate (voir 1.4). |
| `LLMClient.check()` | `GET {url}/models`, puis vérifie que le modèle est listé | **Bloquant** : sovgate n'expose que `/healthz`, `/v1/inspect` et `/v1/chat/completions` (`sovgate/app.py:create_app`). `check()` renvoie une 404, ce qui lève `ActionError` dans `service.triage_alert`. Il faut ajouter `GET /v1/models` à sovgate (renvoyer les `upstreams` de la policy), environ 0,25 j. |
| `LLMClient._openai()` | `POST {url}/chat/completions` avec `model, messages, temperature, max_tokens`, plus `response_format: json_object` si `json_mode`. Aucun `reasoning_effort` en remote. | Compatible. sovgate recopie le corps tel quel et **écrase `model`** par `upstream.model` (`app.chat_completions`), donc `PRIVASOC_LLM_REMOTE_MODEL` devient décoratif et il faut le documenter. `response_format` est transmis tel quel ; son support dépend du fournisseur, à vérifier. |
| `LLMClient._headers()` | Seulement `Authorization: Bearer` | Ni `X-Tenant-Id` ni `X-Session-Id`. sovgate utilise alors `tenant=default` et une session UUID aléatoire par requête. Ce n'est pas faux, mais l'audit ne se relie pas à l'alerte. Ajouter `extra_headers` à `Endpoint` : `X-Tenant-Id: privasoc`, `X-Session-Id: alert-<id>-<n>` (charset `^[A-Za-z0-9_.:-]{1,64}$`, `app._checked_id`). |
| `LLMClient._ollama()` (API native) | Utilisé seulement si `not endpoint.remote` et `/api/tags` répond | Ne concerne pas l'endpoint remote. |
| Réponse | Lit `choices[0].message.content`, `usage`, `finish_reason` | sovgate renvoie la charge utile restaurée, plus les en-têtes `X-Sovgate-Action/Upstream/Request-Id`. privasoc les ignore : il faut les recopier dans `call_log` (`store.log_llm_call`) pour relier les deux journaux d'audit. |
| Erreurs | `resp.raise_for_status()`, puis `httpx.HTTPError` devient `ActionError("LLM error")` dans `service.triage_alert` | sovgate renvoie **403** (`blocked by policy`), **503** (détection fail-closed) et **502** (amont). Dans le flux d'escalade, il faut les capturer et **garder le triage local** avec `escalation: {status: "refused", reason}` au lieu de tout perdre. |
| Timeouts | privasoc 300 s ; sovgate 120 s vers l'amont (`httpx.AsyncClient(timeout=120)`) | Aligner les deux valeurs ou accepter un 502 au-delà de 120 s. |

### 1.2 Ce que sovgate attend (`sovgate/pipeline.py:Gateway.prepare`)

- **Rôles** : `system` n'est pas scanné (`pseudonymise_system: false`), ce qui convient puisque `triage.SYSTEM` est fixe. Le message `user` (preuves) est scanné et pseudonymisé.
- **Contenu non fiable** : est traité comme tel tout message de rôle `tool` ou tout segment `<document>`, `<context>`, `<retrieved>` ou `<search_result>` (`policy.yaml: injection`). privasoc n'envoie aucun des deux, donc `_untrusted_text` retombe sur `scan_scope="all"` et **aucun spotlighting** n'est appliqué (`wrap_segments` ne trouve aucune balise).
  - Changement côté privasoc : dans `triage.build_evidence`, entourer le bloc `evidence:` de `<document source="privasoc-evidence">...</document>`. La règle et sa description restent hors balise.
  - **Échappement obligatoire** : `tag_pattern` est non gourmand (`.*?</document>`). Une ligne de log contrôlée par l'attaquant qui contient `</document>` (URL, user-agent) referme le segment, et la suite échappe au spotlight. Il faut neutraliser `</document` (par exemple `<\/document`) dans les preuves avant l'envoi.
  - Gain secondaire : privasoc n'a **aucune défense contre l'injection** sur son chemin local (aucune occurrence de spotlight dans `src/privasoc`). Or les logs sont, par nature, du contenu écrit par l'attaquant. Porter `guards/spotlight.py` dans `triage.py` profite aussi au modèle local.
- **Scan d'injection** (`guards/injection.py:scan`) : sur des preuves d'attaque web, des motifs comme `override` ou `exfil_markdown` vont légitimement apparaître dans les charges utiles. Avec `on_detect: strip_tools`, l'effet est nul puisque privasoc n'envoie pas d'outils. Il faut **interdire `block`** dans le profil privasoc, sinon les attaques les plus intéressantes ne seraient jamais triées. Le drapeau doit remonter dans le triage comme indice : la preuve contient une tentative d'injection.
- **Notes système** : `_with_system_notes` préfixe `PLACEHOLDER_NOTICE` (si des spans sont trouvés) et l'instruction de frontière au premier message `system`. Pas de conflit avec `triage.SYSTEM`.

### 1.3 Où placer la décision d'escalade

| Rôle | Emplacement | Justification |
|---|---|---|
| Score et décision pure | `detect/triage.py` : nouvelle `reliability(rec, signals) -> dict` et `should_escalate(rec, settings) -> (bool, reasons)` | `triage.py` est déjà pur (prompt, `validate`, `triage`). Testable sans réseau. |
| Orchestration | `service.triage_alert` | C'est là que se décident aujourd'hui le provider, la passe résiduelle et la création du client. Le modèle existe déjà dans `service.propose` (`out.status == "needs_escalation"`, puis `s.auto_fallback`, puis `_generate(..., "remote")`). Il faut le reproduire : triage local, signaux, décision, puis `_local_residual_rules` et triage remote via sovgate, en stockant **les deux** résultats. |
| Configuration | `config.Settings` : `triage_auto_escalate: bool = False`, `triage_escalate_below: float`, `triage_samples: int` | Opt-in, comme `auto_fallback`. |
| Stockage | `alerts.save_triage` (JSON libre) : `{local: {...}, remote: {...}|None, escalation: {score, signals, threshold, decided_by}}` | Aucun schéma SQL à migrer. L'UI de triage doit afficher les deux verdicts. |

### 1.4 Mécanismes existants à réutiliser ou à réviser

| Mécanisme | État | Impact |
|---|---|---|
| `PRIVASOC_AUTO_FALLBACK` (`config.auto_fallback`) | Ne sert qu'à `service.propose` (parseurs) | Ne pas le réutiliser pour le triage : ajouter un drapeau distinct, car le risque n'est pas le même. |
| D34 | Escalade automatique autorisée « quand configurée ou quand le modèle admet sa limite ou hallucine » | Fournit déjà la justification de principe. |
| **D53** | « remote API only on a human action » pour le triage | **Contredit la proposition.** Il faut une nouvelle décision (D57) qui barre et remplace partiellement D53, conformément à `AGENTS.md` : escalade auto opt-in, désactivée par défaut, analyste toujours décisionnaire. |
| D49 / `_local_residual_rules` | Avant tout appel remote, le modèle local relit les `event.original` et ses trouvailles s'appliquent à l'appel | Déjà appelé dans `triage_alert` si `provider == "remote"`. En escalade, il faut **reconstruire les preuves** avec `pz.with_rules(extra)` : le prompt remote diffère alors du prompt local, ce qui est normal. Coût : environ 2 s par lot de 10 lignes (I31). |
| Garde de fuite I10 (`LLMClient.chat`) | Refuse tout original dans le prompt | Reste la garde primaire, avant sovgate. Ne jamais l'affaiblir. |
| `learn.ensure_local` + `endpoint.remote` | Bloque la passe résiduelle vers une IP publique | **Faille potentielle** : si quelqu'un pointe `PRIVASOC_LLM_LOCAL_URL` vers un sovgate sur le LAN, `ensure_local` passe (IP privée), alors que sovgate route vers l'externe (en `passthrough` si rien n'est détecté). Ajouter dans `ensure_local` ou dans `LLMClient.check` une détection de passerelle (`GET /healthz`, en-tête `X-Sovgate-*`) qui refuse. Ne jamais faire passer l'endpoint local par sovgate, qui de toute façon perdrait l'API native et `num_ctx` (I24 : troncature silencieuse à 4 096 tokens). |
| `Reply.prompt_truncated`, `finish_reason` | Déjà calculés | Signaux de fiabilité gratuits (voir section 3). |

---

## 2. Double pseudonymisation : interactions et contrat

### 2.1 Ce que font les détecteurs sovgate sur un texte déjà pseudonymisé par privasoc

Mesures faites avec `sovgate/pii/detectors.py:RegexDetector` sur des chaînes au format privasoc (I2) :

| Jeton privasoc | Détecteur sovgate | Résultat | Gravité |
|---|---|---|---|
| IPv4 `10.x.y.z` / `198.18-19.x.y`, IPv6 `2001:db8::/32` | aucun (pas de type IP dans `policy.yaml`) | passe inchangé, forme conservée | bon pour l'utilité ; aucune défense si privasoc a raté une IP |
| `user-xxxxxx`, `host-xxxxxx`, `dxxxxxx.tld` | aucun en regex ; GLiNER inconnu (`ner.py` non fourni, `backend: none` par défaut) | inchangé en regex ; avec GLiNER à `threshold: 0.3`, risque de PERSON/ORG sur les jetons et sur le vocabulaire de log (noms de vendeurs, de programmes) | moyen : perte sémantique (ORG masqué sur un nom de produit) |
| e-mail `uxxxxxx@dxxxxxx.dyyyyyy.tld` | `EMAIL` | **re-tokenisé** en `<EMAIL_abcdef>` (confirmé) | triage : restauré, donc OK ; **génération de parseur : forme perdue**, la regex écrite sur `<EMAIL_..>` échoue sur les vraies lignes |
| Horodatage epoch en ms (13 chiffres) | `CREDIT_CARD` (Luhn) | **environ 10 %** signalés (mesuré sur 20 000 valeurs) | **élevé** : `restricted`, donc `Action.LOCAL`, donc l'escalade revient silencieusement au modèle local via `/v1` (4 096 tokens) |
| SID `S-1-5-21-a-b-c-RID` (forme des jetons `sid_token`) | `CREDIT_CARD` (le séparateur `-` est autorisé) | **environ 18 %** signalés | élevé : même effet |
| Durée ou compteur commençant par 0 sur 10 chiffres | `PHONE_CH` | signalé (`0412345678`) | moyen : pseudonymisé à tort |
| MAC `02:..` | aucun | inchangé | idem IP |

À retenir :
- **Re-tokenisation** : elle ne touche aujourd'hui que les e-mails. Mais ajouter naïvement à sovgate des types IP, HOSTNAME, MAC ou SID « pour couvrir les logs » reproduirait exactement le bug I33 : un jeton IP est lui-même une IP. On perdrait la forme, la cohérence de sous-réseau (/24) et la distinction privé/public, qui sont des informations de triage.
- **Ré-identification** : `Gateway.restore` rend le jeton privasoc d'origine, puis `Pseudonymizer.reidentify` (privasoc) le résout. La chaîne est correcte tant que les deux étapes s'appliquent dans l'ordre inverse. Deux réserves :
  1. La passe « digest nu » de sovgate (`reidentify` étape 3, `(?<![0-9A-Za-z])<hex6>`) peut s'appliquer à l'hex d'un `user-xxxxxx` (précédé de `-`). Une collision est très improbable (environ 1e-6 par paire) mais déterministe à l'échelle du tenant.
  2. Le coffre sovgate est en mémoire avec TTL (`vault_ttl_seconds=3600`). La ré-identification ultérieure repose entièrement sur le coffre privasoc. Il ne faut donc pas laisser sovgate produire des jetons qui survivraient dans un triage stocké.
- **Routage** : `router.decide` prend la sensibilité maximale. Un seul faux `CREDIT_CARD` suffit à envoyer toute la requête vers `local`.
- **Couverture des types** : `policy.yaml` ne connaît que des entités de documents d'affaires suisses (AHV, IBAN, CREDIT_CARD, DATE_OF_BIRTH, EMAIL, PHONE_CH, PERSON, ORG, ADDRESS, CLIENT, LOCATION). Rien pour IP, HOSTNAME/FQDN, MAC, SID, USERNAME, chemins utilisateur ou URL.

### 2.2 Contrat proposé : privasoc pseudonymise, sovgate vérifie

| Responsabilité | privasoc | sovgate (instance ou profil dédié « privasoc ») |
|---|---|---|
| Pseudonymisation à forme préservée, coffre persistant, ré-identification | **seul responsable** | ne pseudonymise pas les jetons privasoc |
| Garde de fuite sur les originaux connus | `LLMClient.chat` (I10) | (aucun) |
| Détection de fuite résiduelle (valeurs que privasoc n'a pas vues) | passe locale D49 | **vérificateur** : regex « IP hors plages de jetons » (IPv4 hors 10/8 et 198.18/15, IPv6 hors 2001:db8::/32), MAC non `02:`, plus GLiNER PERSON en option. Toute détection donne `block` (403), et privasoc garde le résultat local et crée une proposition de règle D33. |
| Spotlighting et scan d'injection | balise `<document>` échappée | wrap + instruction, `on_detect: flag` (jamais `block`) |
| Point d'egress unique, clé API amont, audit chaîné | journal d'appels (tailles) | audit hash-chaîné, relié par `X-Session-Id` |

Modifications concrètes dans sovgate :
1. **Allowlist de motifs** (`policy.allowlist_patterns`) : les spans recouvrant un jeton privasoc sont retirés dans `Gateway.prepare`, avant `decide` (`(?:user|host)-[0-9a-f]{6}`, `u[0-9a-f]{6}@d[0-9a-f]{6}(?:\.[\w-]+)+`, `d[0-9a-f]{6}(?:\.[\w-]+)+`, les plages IP et MAC de jetons, `S-1-5-21-\d+-\d+-\d+(?:-\d+)?`). Environ 1 j.
2. **Profil de policy privasoc** : retirer ou passer en `public` `CREDIT_CARD`, `PHONE_CH` et `AHV_NUMBER` (faux positifs dans les logs), `ORG` et `LOCATION` en `public`, `restricted: block` (jamais `local`, qui contourne `num_ctx`). Comme sovgate charge **une seule policy par processus** (`create_app`), le plus simple est une instance dédiée (0,25 j). Une policy par tenant coûterait 2 à 3 j.
3. **Nouveaux détecteurs vérificateurs** `UNMAPPED_IP` et `UNMAPPED_MAC` (dans `detectors.py`), de sensibilité `restricted`, donc bloquants. Limite assumée : une IP réelle en 10/8 ratée par privasoc est indiscernable d'un jeton, et un SID ou un nom d'hôte nu ne se vérifient pas par regex.
4. Variante « inspect-then-send » : privasoc appelle d'abord `POST /v1/inspect` (pas d'appel amont, coffre purgé). Si `entities` n'est pas vide après allowlist, c'est une fuite privasoc : il refuse l'envoi et propose une règle. Il n'appelle `/v1/chat/completions` que si rien n'est trouvé. Coût : une détection de plus (environ 200 ms avec GLiNER sur CPU).

Pourquoi pas une double pseudonymisation propre ? Elle n'apporte rien sur les entités que privasoc connaît déjà. Elle détruit la forme, ce qui est fatal pour la génération de parseurs (I9 `real_lines_ok`) et pour le raisonnement sur les sous-réseaux. Et elle produit des jetons non persistants. Le seul cas utile, un nom en clair raté par privasoc, est mieux traité en bloquant puis en apprenant (D33) qu'en masquant silencieusement : masquer cacherait la fuite au mécanisme d'apprentissage.

---

## 3. D'où vient le chiffre de confiance, et est-il exploitable ?

### 3.1 État actuel

`triage.SYSTEM` demande `"confidence": number between 0 and 1`. `triage.validate` se contente de le borner dans [0, 1] et de l'arrondir à 2 décimales (0.0 s'il n'est pas numérique), puis il est stocké. **Aucune décision ne l'utilise.** Température 0.1, `format: json`, et la clé `verdict` est générée avant `reasons` : le chiffre ne repose donc sur aucun raisonnement préalable.

La confiance verbalisée des LLM est connue pour être surconfiante et regroupée vers 0.8 à 0.95 (par exemple Xiong et al., ICLR 2024, *Can LLMs Express Their Uncertainty?*), encore plus pour les petits modèles. Un seuil fixe de 0.70 sur ce chiffre brut se déclencherait quasiment jamais. **Il est inutilisable tel quel.** On le garde comme une caractéristique parmi d'autres.

### 3.2 Signaux disponibles dans le code

| Signal | Source | Coût | Valeur attendue |
|---|---|---|---|
| Réponse non JSON (`result is None`) | `validate` → `problems[0]` | 0 | escalade certaine |
| Verdict ou sévérité inconnus, confiance non numérique | `validate` | 0 | forte |
| Affirmations citant des événements absents, ou n'en citant aucun | `validate` (`reasons[].flag`) | 0 | forte (ancrage, D38b) |
| Entités inventées (`_ENTITY` absent des preuves) | `validate` | 0 | forte (hallucination) |
| ATT&CK mal formé ; ids `in_rule_tags=False` | `validate` (`attack[]`) | 0 | moyenne (le hors-tag n'est pas forcément faux) |
| `verdict == "needs_more_info"` | réponse | 0 | abstention explicite. Escalader, mais le modèle frontière peut aussi manquer d'information. |
| Prompt tronqué (`Reply.prompt_truncated`), `finish_reason == "length"` | `llm.py` | 0 | forte : la preuve n'a pas été vue en entier |
| Asymétrie de risque : verdict `benign`/`false_positive` sur une règle `high`/`critical` | `alert["level"]`, `LEVEL_RANK` | 0 | forte : c'est l'erreur qui coûte cher |
| Écart entre la sévérité du modèle et le niveau de la règle | `validate` + règle | 0 | faible à moyenne |
| Volume de preuve (nombre d'événements, `alert.count`), origine de la règle (SigmaHQ, privasoc, ai) | `build_evidence`, `rule.origin` | 0 | caractéristique de contexte |
| **Auto-cohérence** : N échantillons à T = 0.7, taux d'accord sur le verdict, dispersion de la sévérité | N appels à `triage.triage` | N × 4 à 12 s sur GPU 8 Go (I32, I34), un seul GPU. Tourne en tâche de fond. | forte, et c'est le meilleur signal sans logprobs |
| **Logprobs du verdict** | API native Ollama : `/api/chat` accepte `logprobs: true` et `top_logprobs: k`, et renvoie `logprobs[]` (`token`, `logprob`, `top_logprobs`). La page OpenAI compatibility d'Ollama liste en revanche *Logprobs* et `n` comme **non supportés** sur `/v1`. privasoc utilise déjà l'API native en local (I24, `_ollama`), il suffit donc d'ajouter les deux champs. | presque gratuit (un seul appel) | forte : probabilité du premier token du verdict (`true` / `benign` / `false` / `needs`) normalisée sur les 4 candidats. À valider : interaction avec `format: json` (décodage contraint), version d'Ollama du poste, tokenisation de Qwen3. |
| Historique par règle : accord passé entre verdict local et clôture analyste (`closed_tp` / `closed_fp`) pour ce `rule_id` | table `alerts` (D52) | 0 une fois les données là | forte à terme ; nul au démarrage |
| Indicateur d'injection sovgate (`X-Sovgate-*` / audit) | sovgate | 0 | contexte (la preuve contient une attaque contre le modèle) |

### 3.3 Combinaison en un score calibré

1. **Définir la cible** : `y = 1` si le verdict local est correct par rapport à la clôture analyste. `closed_tp` correspond à `true_positive` ; `closed_fp` correspond à `benign` ou `false_positive` ; `resolved` est ignoré (alerts.resolve) ; `needs_more_info` est traité à part, comme une abstention.
2. **Portes dures, sans apprentissage (MVP)** : escalader si réponse invalide, si `problems` non vide (ancrage ou invention), si troncature, si `needs_more_info`, ou si l'asymétrie est présente.
3. **Score appris** : régression logistique régularisée sur 5 à 7 caractéristiques (accord d'auto-cohérence, p(verdict) par logprob, nombre de problèmes, asymétrie, confiance déclarée, nombre d'événements), suivie d'une calibration isotone ou de Platt. Avec moins de 100 exemples, se limiter à 2 ou 3 caractéristiques.
4. **Évaluer** : ECE et diagramme de fiabilité, Brier, AUROC de « verdict correct », et surtout la **courbe risque-couverture** (erreur résiduelle en fonction du taux d'escalade).
5. **Choisir le seuil par le coût, pas par principe** : escalader si `(q - p) * C_erreur > C_escalade`, où `p` est le score calibré du local et `q` la précision mesurée du modèle frontière sur des preuves pseudonymisées. Le seuil vaut donc `p* = q - C_escalade / C_erreur`. Il faut deux seuils, un plus permissif quand le verdict local est « bénin » sur une règle haute (coût d'un faux négatif), et fixer un plafond de taux d'escalade (budget, exposition). « 70 % » ne devient défendable que s'il sort de ce calcul.
6. **Mise en garde** : l'avantage du modèle frontière vient en partie de sa connaissance du monde (réputation de domaines, d'IP, d'outils). Or privasoc pseudonymise **tous** les domaines et IP publics (D15 ; question ouverte déjà notée en I33). Il faut mesurer `q` avant de construire quoi que ce soit. Si `q - p` est faible, l'escalade ne vaut pas son coût de confidentialité.

---

## 4. Faisabilité par composant, effort et plan

### 4.1 Tableau (1 développeur, jours ouvrés)

| # | Composant | Fichiers touchés | Difficulté | Effort |
|---|---|---|---|---|
| A | `GET /v1/models` dans sovgate | `sovgate/app.py` | facile | 0,25 |
| B | En-têtes tenant/session, lecture des en-têtes `X-Sovgate-*` vers `call_log`, gestion 403/502/503 | `privasoc/llm.py` (`Endpoint`, `_headers`, `Reply`) | facile | 0,5 |
| C | Garde « jamais de passerelle pour le local » | `privasoc/pseudo/learn.py:ensure_local`, `llm.py:check` | facile | 0,5 |
| D | Preuves dans `<document>` échappé, plus spotlight local | `detect/triage.py:build_evidence`, `SYSTEM` | facile | 0,5 à 1 |
| E | Profil sovgate privasoc : allowlist de jetons, retrait des faux positifs CC/PHONE/AHV, `restricted: block`, détecteurs vérificateurs IP/MAC | `sovgate/pipeline.py`, `pii/detectors.py`, `config.py`, `config/policy.privasoc.yaml` | moyen | 2 |
| F | Inspect-then-send et remontée en proposition de règle | `service.triage_alert`, `vault.add_rule` | moyen | 1 à 1,5 |
| G | Orchestration de l'escalade et stockage double (local + remote), D57, tests | `service.triage_alert`, `detect/triage.py`, `config.py`, `alerts.save_triage`, UI de triage | moyen | 2 à 3 |
| H | Signaux gratuits (problèmes, troncature, asymétrie, `needs_more_info`) | `detect/triage.py` | facile | 0,5 |
| I | Auto-cohérence N échantillons (tâche de fond, GPU unique) | `detect/triage.py`, file de tâches (comme I30) | facile à moyen | 1 |
| J | Logprobs (API native, alignement des tokens du verdict, repli si absent) | `llm.py:_ollama`, `Reply`, `triage.py` | moyen (dépend de la version) | 1,5 à 2 |
| K | **Étape 8 : banc de triage étiqueté** (scénarios synthétiques déterministes TP/FP/bénin, dev/holdout, plus les alertes réelles clôturées) et harnais (précision, abstention, ECE, AUROC, risque-couverture, local vs frontière via sovgate) | `evaluation/`, CLI `eval triage` | **difficile** | 5 à 8 |
| L | Calibration, choix du seuil, rapport | `evaluation/`, `triage.py` (coefficients versionnés) | moyen | 2 |
| M | Historique par règle | `alerts.py`, `triage.py` | facile | 0,5 |
| N | Policy par tenant dans sovgate (si l'instance est partagée avec d'autres applis) | `sovgate/app.py`, `config.py` | moyen | 2 à 3 (optionnel) |

Total : MVP (A, B, C, D, E, G, H) environ **6 à 8 j** ; version complète environ **20 à 26 j**.

### 4.2 Plan par phases

| Phase | Contenu | Critère de sortie |
|---|---|---|
| **0. Prérequis** (K, partie « mesure ») | Banc de triage étiqueté. Mesurer la précision locale `p`, la calibration de `confidence` brute, et `q` du frontière **déjà possible aujourd'hui** par action humaine (`--provider remote`, D53), sans sovgate | Feu vert seulement si `q - p` est significatif sur le holdout et si l'AUROC d'au moins un signal dépasse nettement 0.5 |
| **1. Tuyauterie MVP** (A à E) | remote → sovgate en mode vérificateur, `<document>`, audit relié, **toujours sur action humaine** (D53 inchangé) | 0 fuite et 0 routage `local` parasite sur le banc (via `/v1/inspect`) ; tests de non-régression de la garde I10 |
| **2. Escalade par règles** (G, H) | Portes dures, drapeau opt-in `triage_auto_escalate`, D57 | Taux d'escalade et gain d'erreur publiés sur le holdout |
| **3. Score calibré** (I, J, L, M) | Auto-cohérence, logprobs, logistique + isotone, seuil dérivé du coût | ECE < 0.1 et courbe risque-couverture publiée ; seuil justifié chiffre à l'appui |
| **4. Extension** (F, section 5) | Parseurs et règles Sigma via sovgate, inspect-then-send, apprentissage depuis les blocages sovgate | Métriques I26 et D56 refaites en local, local+escalade, remote |

---

## 5. Étendre l'escalade aux autres tâches IA ?

| Tâche | Signal d'échec | Recommandation |
|---|---|---|
| **Génération de parseurs** (`service.propose`, `generator.generate`) | **Objectif** et déjà en place : `needs_escalation` (statut auto-déclaré D38a, stagnation D38c, compilation, couverture, ancrage), puis `auto_fallback` | **Oui, et c'est le cas le plus facile.** Il suffit de router l'endpoint remote via sovgate. **Condition stricte** : l'allowlist du point E, sinon `EMAIL` re-tokenise `u..@d..` et la spec est écrite sur `<EMAIL_..>`, ce qui fait échouer `real_lines_ok`. `PLACEHOLDER_NOTICE` ne doit jamais apparaître ici. |
| **Règles Sigma et hunting** (`service.author_rule`, `author.write`) | Partiellement objectif : `draft.status != "proposed"` après 3 tentatives, ou backtest à 0 ou à un nombre aberrant de correspondances. En revanche, « valide mais faux » (holdout D56 : 47 % exact) n'a pas de signal fiable. | **Oui sur l'échec de validation**. Sur action humaine sinon. Attention : le texte de règle SigmaHQ (champ `author`) contient des noms de personnes, que GLiNER masquerait. C'est sans danger (restauré), mais la passe D49 sur le texte de règle (I35) reste prioritaire. Le problème I33 (regex écrite sur la forme pseudonymisée d'un domaine) touche aussi le frontière. |
| **Pseudonymisation apprise** (`learn.residual_pass`) | (aucun) | **Jamais en remote (D49).** Le texte contient des valeurs en clair par conception (`originals=set()`). Ni escalade, ni sovgate : ajouter la garde C pour qu'un sovgate sur le LAN ne puisse pas passer pour « local ». Le seul lien autorisé va dans l'autre sens : un blocage du vérificateur sovgate produit une proposition de règle locale. |
| **Triage** | Signaux de la section 3 | Oui, après la phase 0 seulement. |

---

## Annexe : points de vigilance pour les décisions (à journaliser)

- D57 (proposée) : escalade automatique du triage opt-in, désactivée par défaut, analyste décisionnaire ; elle remplace partiellement D53.
- D58 (proposée) : sovgate est vérificateur et point d'egress, jamais second pseudonymiseur des jetons privasoc ; `restricted: block`, jamais `local`.
- I-note : faux positifs mesurés de `CREDIT_CARD` (environ 10 % des epoch-ms, environ 18 % des SID) et de `PHONE_CH` sur des logs ; re-tokenisation des e-mails pseudonymisés.
- I-note : `ensure_local` se contourne avec un sovgate sur IP privée. Il faut une garde explicite.
