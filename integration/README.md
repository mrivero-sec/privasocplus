# Tests d'intégration privasoc + sovgate

Vérifient le contrat entre les deux paquets (DECISIONS PD5, PD8, PD9, PD20) avec du vrai code des deux côtés et un faux modèle frontière. Aucune clé API, aucun réseau externe.

| Test | Vérifie |
|---|---|
| `test_tokens_pass_untouched_and_nothing_original_leaves` | les jetons privasoc arrivent intacts au fournisseur, aucune valeur réelle ne sort, preuves spotlightées, audit sans valeur |
| `test_value_missed_by_privasoc_is_blocked` | une IP non pseudonymisée est bloquée par sovgate (403, types seulement) |
| `test_injection_in_a_log_field_is_flagged` | une injection dans un champ de log devient un problème de triage |
| `test_residual_pass_refuses_the_gateway` | la passe locale D49 refuse une passerelle |
| `test_unminted_token_shaped_address_never_leaves` (4 cas) | une adresse oubliée dans les plages de jetons ou une MAC `02` est bloquée, sans valeur dans le refus ou l'audit |

## Lancer

Depuis la racine du dépôt :

```bash
uv sync --all-packages
uv run pytest -q integration
```

Le profil est lu dans `packages/gateway/config/policy.privasoc.yaml` (`SOVGATE_DIR` permet d'en désigner un autre).

Le profil strict exige une clé de client et un manifeste `_privasoc_address_tokens` issu
du coffre local. Il est retiré avant l'amont. Les huit tests utilisent uniquement un
fournisseur simulé ; ils ne mesurent ni la qualité du triage ni la détection réelle de GLiNER.

`test_deploy_contract.py` ajoute trois contrôles avec le client Docker Compose, sans
démarrer de conteneur : activation explicite du distant, séparation des réseaux et des
secrets, NER et modèle effectif cohérents. Aucun `.env` réel n'est lu. Si le client Docker
est absent, seuls ces trois contrôles sont ignorés. Résultat de la revue : 11 passants.

Sous Windows, la même commande `uv run pytest -q integration` fonctionne depuis la racine.
Si le dossier temporaire système est inaccessible, choisir `--basetemp` dans un dossier
de travail dédié. La communication loopback doit être autorisée.
