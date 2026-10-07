# privasoc+

**Un SOC local qui trie ses alertes avec un petit LLM local, et ne demande un second avis à un modèle frontière qu'à travers une passerelle qui vérifie que rien de personnel ne sort.**

privasoc+ réunit deux briques dans un seul dépôt :

- **privasoc** : collecte de logs (Vector), parseurs écrits par le modèle local et approuvés par un humain, détection Sigma, triage structuré des alertes, banc d'évaluation. Tout est pseudonymisé avant d'atteindre un modèle, même local.
- **sovgate** : passerelle de sortie compatible OpenAI. Pour privasoc, elle ne pseudonymise pas une seconde fois : elle **vérifie** que seuls des jetons émis par privasoc sortent, isole les preuves (spotlighting contre l'injection) et tient un journal d'audit chaîné.

Assistants IA : commencez par [AGENTS.md](AGENTS.md).

## État (2026-10-07)

| Phase | État |
|---|---|
| P1 Sortie sécurisée privasoc vers sovgate | implémentée, testée avec un fournisseur simulé ; Docker et NER réel encore à valider |
| P0 Mesure du triage | banc de 38 cas et harnais livrés, seuils fixés avant toute mesure ; **aucun résultat de modèle encore** |
| P2 à P10 Enrichissement, signaux, routage, fiche de faits | à faire ([plan](docs/INTEGRATION_PLAN.md)) |

Le triage distant reste une action humaine : rien n'escalade automatiquement. Détail et reprise : [docs/PROGRESS.md](docs/PROGRESS.md).

## Architecture

![Architecture v3](diagram/architecture-v3.png)

1. **Enrichir d'abord** avec du contexte local (historique de l'hôte, alertes passées de la règle, inventaire, IOC locaux), puis relancer le triage local.
2. **Détecter l'incertitude par des faits** : désaccord entre deux modèles locaux, affirmations du modèle vérifiées dans la base, contrôles de validation. La confiance que le modèle se donne n'est qu'un signal secondaire ([pourquoi](docs/alternatives.md)).
3. **Router selon l'enjeu** vers le local, un modèle frontière ou l'analyste. Un verdict « bénin » sur une alerte grave va toujours à l'analyste ; le modèle frontière n'abaisse jamais seul un verdict.
4. **Envoyer une fiche de faits**, pas les logs : résumé structuré et pseudonymisé, sans chaînes contrôlées par l'attaquant.
5. **privasoc pseudonymise, sovgate vérifie** : seule la passerelle a accès au fournisseur ; une adresse absente du manifeste de jetons bloque l'envoi.
6. **Mesurer en continu** par audit aléatoire des alertes closes ; plus tard, routage appris et modèle frontière « professeur » du modèle local.

Les points 1 à 4 et 6 sont planifiés ; le point 5 et la mesure (banc de triage) sont implémentés.

## Organisation

| Chemin | Contenu |
|---|---|
| [packages/privasoc](packages/privasoc) | SOC local (paquet `privasoc`, CLI `privasoc`) |
| [packages/gateway](packages/gateway) | passerelle sovgate (paquet `sovereign-llm-gateway`) |
| [integration/](integration/) | tests de contrat entre les deux |
| [deploy/](deploy/) | composition Docker : privasoc, Vector, modèle local, passerelle en option |
| [docs/](docs/), [diagram/](diagram/) | conception, décisions, plan, avancement |

Un workspace [uv](https://docs.astral.sh/uv/) : un `pyproject.toml` et un `uv.lock` à la racine.

## Démarrer

Prérequis : uv, le binaire [Vector](https://vector.dev/download/) (bac à sable des parseurs) et un serveur compatible OpenAI pour le modèle local, par exemple [Ollama](https://ollama.com) avec `qwen3:8b`.

```bash
uv sync --all-packages
cd packages/privasoc
uv run privasoc init                 # écrit .env avec des secrets neufs ; y régler le modèle et Vector
uv run privasoc serve                # API et interface de revue sur http://127.0.0.1:8000/ui/
```

Le guide complet de privasoc (onboarding d'une source, parseurs, détection, triage, hunting) est dans [packages/privasoc/README.md](packages/privasoc/README.md) ; celui de la passerelle dans [packages/gateway/README.md](packages/gateway/README.md). Déploiement Docker : [deploy/README.md](deploy/README.md).

### Mesurer le triage

```bash
cd packages/privasoc
uv run privasoc eval triage --set all --runs 3     # modèle local
uv run privasoc eval triage-report                 # reports/triage.md
```

Protocole et seuils, fixés avant tout résultat : [docs/DECISIONS.md](docs/DECISIONS.md) (PD23) et le journal historique de privasoc (D57).

### Tests

```bash
uv run ruff check .
(cd packages/privasoc && uv run pytest -q)       # les tests Vector sont ignorés sans le binaire
(cd packages/gateway && uv run pytest -q)
uv run pytest -q integration
```

## Documentation

| Fichier | Contenu |
|---|---|
| [docs/PROGRESS.md](docs/PROGRESS.md) | ce qui est fait, comment le vérifier, prochaines actions |
| [docs/DECISIONS.md](docs/DECISIONS.md) | journal des décisions (PD), constats (N), questions ouvertes (Q) |
| [docs/INTEGRATION_PLAN.md](docs/INTEGRATION_PLAN.md) | plan en 11 phases et suivi |
| [docs/CONTEXT.md](docs/CONTEXT.md) | fonctionnement des deux paquets |
| [docs/alternatives.md](docs/alternatives.md) | pourquoi pas un simple seuil de confiance |
| [docs/metrics.md](docs/metrics.md) | calibration, règle de coût, métriques, protocole d'évaluation |
| [docs/constraints.md](docs/constraints.md) | sécurité, vie privée et droit, exploitation |
| [docs/feasibility.md](docs/feasibility.md) | analyse d'intégration initiale |
| [docs/MANUAL_SAMPLES.md](docs/MANUAL_SAMPLES.md) | essais d'ingestion sur des samples publics |
| [diagram/diagram-notes.md](diagram/diagram-notes.md) | notes des diagrammes (v3 actuelle, v1 et v2 historiques) |
| [packages/privasoc/docs/DECISIONS.md](packages/privasoc/docs/DECISIONS.md) | journal historique de privasoc (D1 à D62, I1 à I48), figé |

## Limites connues

- La confiance déclarée par un modèle 8B est surconfiante et manipulable par injection ; elle ne sert pas seule à router ([metrics.md](docs/metrics.md)).
- Les preuves de triage ne contiennent que les événements qui ont déclenché la règle, et les noms de domaine et d'utilisateur pseudonymisés masquent ce qui les rendait suspects (constat N27) : c'est l'objet des phases P2 et P5.
- Un serveur de modèle inconnu sur le réseau local reste un composant de confiance (N28).
- Des logs pseudonymisés restent des données personnelles : prérequis juridiques avant tout usage sur des données de tiers ([constraints.md](docs/constraints.md)). Rien ici n'est un avis juridique.

## Licence

MIT, voir [LICENSE](LICENSE). Le modèle NER par défaut de la passerelle, `urchade/gliner_multi_pii-v1`, est sous Apache-2.0 ; les règles SigmaHQ (DRL 1.1) et les fixtures Elastic (ELv2) sont téléchargées à l'exécution et jamais committées.
