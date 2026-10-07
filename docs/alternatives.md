# privasoc+ : alternatives au seuil de confiance

Session de conception du 2026-10-07. Ce document explique pourquoi l'architecture ne repose plus sur « confiance locale < 70 % : escalade », et quelles idées la remplacent. Les décisions qui en découlent sont dans [DECISIONS.md](DECISIONS.md) (PD10 à PD18), leur mise en oeuvre dans [INTEGRATION_PLAN.md](INTEGRATION_PLAN.md).

## Point de départ

Le seuil de confiance ne répond qu'à une question : « le modèle local est-il sûr de lui ? ». Or :

- la confiance d'un modèle 8B est auto-déclarée, surconfiante, et manipulable par du texte injecté dans un log (voir [metrics.md](metrics.md) section 1 et [constraints.md](constraints.md) S2) ;
- un seuil n'envoie au modèle frontière que les cas où le local doute, jamais ceux où il se trompe avec assurance : on ne mesure donc jamais le vrai taux d'erreur local ;
- beaucoup d'incertitudes viennent d'un **manque de contexte**, pas d'un manque d'intelligence ;
- envoyer les preuves brutes (même pseudonymisées) expose des données personnelles et des chaînes contrôlées par l'attaquant.

Les alternatives ci-dessous changent quatre choses : **ce qui déclenche** l'escalade, **vers quoi** on escalade, **ce qu'on envoie**, et **quand** le modèle frontière intervient.

## A. Ce qui déclenche l'escalade

| ID | Idée | Principe | Pourquoi c'est mieux qu'un seuil | Coût / limite |
|---|---|---|---|---|
| A1 | **Désaccord entre deux modèles locaux** | Deux modèles locaux de familles différentes (ex. Qwen et Llama, Gemma ou Mistral) triagent la même alerte ; un désaccord sur la classe de décision déclenche l'escalade | Signal d'incertitude bien meilleur qu'un pourcentage déclaré ; plus dur à manipuler par injection (il faut tromper deux modèles de la même façon) ; reste 100 % local | Deux passes GPU ; deux modèles qui se trompent ensemble restent invisibles (d'où l'audit C2) |
| A2 | **Affirmations vérifiables** | Le modèle local formule des affirmations structurées (`claim`: compte, séquence, champ, valeur) que privasoc vérifie par requête sur SQLite ; une affirmation fausse déclenche l'escalade | Prolonge la validation des citations qui existe déjà (D53) ; vérifie les faits, pas l'assurance | Seules les affirmations factuelles se vérifient, pas l'interprétation |
| A3 | **Routage par l'enjeu** | Sévérité de la règle, criticité de l'actif et sens du verdict décident, quelle que soit la confiance : un « bénin » sur une alerte critique reçoit toujours un second avis ; un vrai positif mineur n'en a jamais besoin | Vise l'erreur coûteuse (le faux négatif grave), pas l'incertitude en général | Il faut un inventaire minimal des actifs (criticité) |
| A4 | **Prédiction conforme** | Le score donne un ensemble de verdicts plausibles avec une couverture garantie (ex. 95 %) ; plus d'un verdict dans l'ensemble déclenche l'escalade | Remplace un seuil arbitraire par une garantie statistique | Demande quelques centaines de cas étiquetés et l'échangeabilité (à recalibrer à chaque changement de modèle) |
| A5 | Auto-cohérence (déjà prévue) | k réponses du même modèle ; faible accord = incertain | Gratuit en données | Moins informatif que A1 (même modèle, mêmes biais) |

## B. Vers quoi on escalade

| ID | Idée | Principe | Intérêt |
|---|---|---|---|
| B1 | **Enrichir d'abord** | Avant tout appel externe, ajouter du contexte **local** : historique de l'hôte (santé D47), alertes passées de la même règle et leurs clôtures, flux IOC local, inventaire des actifs ; puis relancer le triage local | Beaucoup de `needs_more_info` disparaissent ; gratuit ; rien ne sort |
| B2 | **Trois destinations** | Local, frontière ou analyste, selon qui est le meilleur pour ce type de cas (cadre *learning to defer*) | Le modèle frontière n'est pas toujours le bon recours : sur données pseudonymisées il perd la réputation des domaines et des IP |

## C. Ce qu'on envoie au modèle frontière

| ID | Idée | Principe | Intérêt | Limite |
|---|---|---|---|---|
| C1 | **Fiche de faits** | privasoc calcule localement un résumé structuré (comptes, séquence temporelle, ports, rythme, techniques ATT&CK candidates, résultats de A2) ; le modèle frontière raisonne sur la fiche, pas sur les logs | Minimisation forte des données personnelles ; les chaînes contrôlées par l'attaquant disparaissent, ce qui traite l'essentiel de l'injection | Le résumé peut omettre l'indice décisif ; d'où C2 |
| C2 | **Enquête par outils** | Le modèle frontière reçoit la fiche et peut demander des champs précis (« les User-Agent de cette source ») via des outils ; chaque appel est pseudonymisé, plafonné et audité par sovgate | « Besoin d'en connaître » : seules les données utiles sortent ; sovgate gère déjà les arguments d'outils | Plus d'allers-retours ; liste d'outils à garder courte et en lecture seule |

## D. Quand le modèle frontière intervient

| ID | Idée | Principe | Intérêt |
|---|---|---|---|
| D1 | **Professeur plutôt que recours** | Hors ligne, sur données synthétiques ou cas difficiles déjà pseudonymisés : il améliore règles Sigma, prompts et exemples, voire produit des données pour affiner le modèle local (LoRA) | Le local s'améliore, les escalades diminuent ; le plus favorable à la vie privée |
| D2 | **Audit aléatoire** | Une petite part (ex. 3 %) des alertes closes est relue au hasard (fiche de faits, en lot) | Seule mesure **non biaisée** du taux d'erreur local, y compris les erreurs sûres d'elles ; fournit les données de calibration |
| D3 | **Lots** | Les cas non urgents partent en lot (ex. quotidien) | Moins cher (les API batch sont souvent facturées environ moitié prix), pas de pression de latence |

## Combinaison retenue

1. **Enrichissement local d'abord** (B1).
2. **Déclencheurs** : règles d'enjeu (A3) + désaccord entre deux modèles (A1) + affirmations fausses (A2) + signaux de validation existants ; la confiance déclarée et l'auto-cohérence (A5) restent des signaux secondaires.
3. **Trois destinations** (B2) : local, frontière, analyste. L'analyste reste la destination par défaut des cas graves.
4. **Charge utile** : fiche de faits (C1), enquête par outils en option (C2). Jamais les logs bruts par défaut.
5. **Mesure** : audit aléatoire (D2), en lot (D3).
6. **À terme** : score calibré ou prédiction conforme (A4) quand les données existent, et modèle frontière comme professeur (D1) pour que l'escalade devienne l'exception.

Le seuil calibré de [metrics.md](metrics.md) devient un signal parmi d'autres, plus le mécanisme central.

## Références

- Angelopoulos, Bates. *A Gentle Introduction to Conformal Prediction and Distribution-Free Uncertainty Quantification*, 2021. https://arxiv.org/abs/2107.07511
- Mozannar, Sontag. *Consistent Estimators for Learning to Defer to an Expert*, ICML 2020. https://arxiv.org/abs/2006.01862
- Chen, Zaharia, Zou. *FrugalGPT: How to Use Large Language Models While Reducing Cost and Improving Performance*, 2023 (cascades de modèles). https://arxiv.org/abs/2305.05176
- Ong et al. *RouteLLM: Learning to Route LLMs with Preference Data*, 2024. https://arxiv.org/abs/2406.18665
- Références sur la calibration de la confiance verbalisée : voir [metrics.md](metrics.md) section 1.
