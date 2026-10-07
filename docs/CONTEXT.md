# privasoc+ : contexte des deux projets sources

Ce dossier ne contient pas le code des deux projets. Ce résumé suffit pour comprendre la conception ; pour modifier le code, il faut les deux dépôts séparés `privasoc` et `sovereign-llm-gateway`. État des dépôts au 2026-10-07.

## privasoc

**Ce que c'est.** Un outil SOC local et respectueux de la vie privée : collecte de logs, normalisation en ECS, détection Sigma, triage et rédaction de règles par un petit LLM local. Python (uv, FastAPI, Typer, pydantic), SQLite, Vector, licence MIT, dépôt public et anonyme.

**État.** Étapes 1 à 7 sur 8 terminées. Reste l'étape 8 : évaluation du triage et collecte Windows / Proxmox. privasoc+ s'appuie directement sur cette étape 8.

**Chaîne.**
1. Vector reçoit syslog ou fichiers ; un nouvel émetteur est mis en attente jusqu'à approbation humaine (D45).
2. Formats connus : parseurs intégrés de Vector. Formats inconnus : quarantaine, puis le LLM local propose un parseur (spec YAML compilée en VRL, bac à sable, contrôles d'ancrage), approuvé par un humain, puis rattrapage de la quarantaine.
3. Détection : moteur Sigma maison (règles privasoc + sous-ensemble SigmaHQ, corrélations Sigma 2), alertes de santé des hôtes et de nouvel émetteur (D47, D50 à D52).
4. **Triage IA** (D53) : modèle local par défaut ; distant seulement sur action humaine, toujours sur preuves pseudonymisées. Entrée : la règle, jusqu'à 20 événements, santé de l'hôte. Sortie validée : `verdict` (true_positive, benign, false_positive, needs_more_info), `severity`, `confidence` (auto-déclarée, 0 à 1), `summary`, `reasons` citant des identifiants d'événements qui doivent exister, `next_steps`, techniques ATT&CK. L'analyste clôt l'alerte en vrai ou faux positif (D52), ce qui sert de vérité terrain.
5. Hunting en langage naturel et règles Sigma écrites par le modèle, avec backtest et approbation humaine (D54 à D56).

**Vie privée.**
- Pseudonymisation à forme préservée, par HMAC à clé : utilisateur `user-xxxxxx`, hôte `host-xxxxxx`, IP privée vers 10/8, IP publique vers 198.18.0.0/15 (cohérence /24), IPv6 vers 2001:db8::/32, MAC `02:…`, e-mails `uxxxxxx@<domaine jeton>` (D15, D25, I2).
- Coffre local chiffré (Fernet) pour ré-identifier les réponses à l'affichage seulement (I5).
- **Contrat strict de sortie** (D60/I43) : le client déclare les seuls jetons IP/MAC issus du coffre et présents dans la requête ; le profil sovgate dédié bloque toute adresse non déclarée, même de forme autorisée.
- **Garde-fou de fuite** : `LLMClient.chat` refuse tout message contenant une valeur originale, quel que soit le fournisseur (I10).
- **Pseudonymisation apprise** (D49) : le modèle local repère les noms restés en clair et propose des règles approuvées par un humain ; cette passe lit du texte en clair, donc ne parle qu'à un modèle local (`ensure_local`), et s'exécute avant tout appel distant.
- Anonymat du dépôt (D43) : aucun nom réel, adresse réelle, domaine privé.

**Chiffres publiés** (modèle `qwen3:8b`, GPU grand public de 8 Go) :
- génération de parseurs, mode structuré : pass@1 70 %, F1 0,53 quand un parseur est proposé, 0 valeur inventée sur 90 essais ; référence écrite à la main F1 0,87 ;
- fuite de pseudonymisation : 8,1 % des valeurs sensibles avec les détecteurs, 3,9 % avec les règles apprises (jeu dev) ;
- hunting : 83 % de réponses exactes en dev, 47 % en holdout ;
- triage : 4 à 12 s par alerte, structure valide ; **pas encore évalué en qualité** (étape 8).

**Points d'entrée utiles.** `src/privasoc/llm.py` (`LLMClient`, `Endpoint`, `Reply`, choix local / distant), `src/privasoc/detect/triage.py` (`build_evidence`, `validate`, `SYSTEM`), `src/privasoc/detect/alerts.py`, `src/privasoc/service.py` (`triage_alert`, `propose` avec `auto_fallback`), `src/privasoc/pseudo/` (`engine`, `tokens`, `vault`, `learn`).

**Décisions citées dans ce dossier.** D15, D25 (pseudonymisation), D33 (règles apprises), D34 (repli distant), D43 (anonymat), D45 (onboarding), D47 (santé des hôtes), D49 (passe locale), D52 (alertes et clôtures), D53 (triage), D54 à D56 (règles IA et hunting), I2 (formats de jetons), I10 (garde-fou de fuite), I24 (fenêtre de contexte Ollama), I26 (résultats parseurs), I30 (une tâche GPU à la fois), I33 (bug de double pseudonymisation). D57 est le protocole de mesure du triage (étape 8) ; l'escalade automatique optionnelle (PD7) sera D58. I40 à I42 : travaux privasoc+ (passerelle, motif de clôture, banc de triage).

## sovereign-llm-gateway (sovgate)

**Ce que c'est.** Une passerelle compatible OpenAI placée entre une application et les fournisseurs de modèles : l'application change seulement son `base_url`. Python, FastAPI, licence MIT, dépôt public.

**Chaîne d'une requête** (`pipeline.Gateway.prepare`, puis `restore`) :
1. détection d'entités : regex avec sommes de contrôle (AVS, IBAN, cartes, téléphones suisses, e-mails), dictionnaire, GLiNER multilingue (noms, organisations, adresses), propagation des noms entre messages ;
2. scan d'injection et **spotlighting** du contenu non fiable (rôle `tool`, balises `<document>`, `<context>`…) avec des frontières aléatoires par requête ; en cas de détection : `flag`, `strip_tools` ou `block` ;
3. routeur de sensibilité (`router.decide`) : `public` passe, `confidential` est pseudonymisé, `restricted` va au modèle local ;
4. pseudonymisation par jetons HMAC typés (`<PERSON_3f9a1c>`), portée tenant ou session, coffre ;
5. ré-identification de la réponse, y compris dans le JSON des appels d'outils ;
6. journal d'audit chaîné par hachage, sans valeurs brutes ; fail-closed (503) si un détecteur plante.

**Chiffres publiés.** Fuite résiduelle 2,1 % (jeu gold) et 1,7 % (synthétique) contre 17,9 % à 33,8 % pour Presidio ; précision 96 à 97 % ; environ 200 ms par document sur 2 cœurs CPU ; pas de perte mesurable de qualité de réponse sur 108 questions RAG. Jeux de données : textes d'affaires en anglais, français et allemand, **pas des logs**.

**Points d'entrée utiles.** `src/sovgate/app.py` (`create_app`, `/v1/chat/completions`, `/v1/inspect`), `pipeline.py`, `router.py`, `pii/detectors.py`, `pii/pseudonymizer.py`, `guards/injection.py`, `guards/spotlight.py`, `audit.py`, `config/policy.yaml`.

## Pourquoi les fusionner

privasoc a déjà un chemin distant (triage sur action humaine, repli de génération de parseurs) protégé par sa propre pseudonymisation ; sovgate apporte un point de sortie unique, une seconde vérification indépendante, le spotlighting contre l'injection et un audit chaîné. privasoc+ définit comment et quand une alerte franchit ce point de sortie.
