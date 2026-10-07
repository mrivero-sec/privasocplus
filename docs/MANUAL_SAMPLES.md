# Échantillons publics pour import manuel

Les fichiers sont dans `privasoc/data/samples-manual/2026-10-07/`, hors de `data/inbox/` surveillé par Vector. Les sept imports ont ensuite été lancés automatiquement à la demande de l’opérateur, soit 6 111 lignes non vides. Les commandes ci-dessous documentent la procédure ; ne pas les relancer sur cette base sans traiter les doublons.

| Fichier | Format | Lignes non vides | Source |
|---|---|---|---|
| `loghub-openssh.log` | SSH : authentification | 2000 | [origine](https://raw.githubusercontent.com/logpai/loghub/dd61d0952749ee7963bde24220d1be5ede023033/OpenSSH/OpenSSH_2k.log) |
| `loghub-linux.log` | Linux : système | 2000 | [origine](https://raw.githubusercontent.com/logpai/loghub/dd61d0952749ee7963bde24220d1be5ede023033/Linux/Linux_2k.log) |
| `loghub-apache-error.log` | Apache : erreurs | 2000 | [origine](https://raw.githubusercontent.com/logpai/loghub/dd61d0952749ee7963bde24220d1be5ede023033/Apache/Apache_2k.log) |
| `elastic-apache-access.log` | Apache : accès HTTP | 17 | [origine](https://raw.githubusercontent.com/elastic/integrations/354ff4c940c3bbd6fcc709d9767bd5a9e12a22bc/packages/apache/data_stream/access/_dev/test/pipeline/test-access-basic.log) |
| `elastic-nginx-access.log` | Nginx : accès HTTP | 14 | [origine](https://raw.githubusercontent.com/elastic/integrations/354ff4c940c3bbd6fcc709d9767bd5a9e12a22bc/packages/nginx/data_stream/access/_dev/test/pipeline/test-access.log) |
| `elastic-checkpoint.log` | Check Point : pare-feu | 53 | [origine](https://raw.githubusercontent.com/elastic/integrations/354ff4c940c3bbd6fcc709d9767bd5a9e12a22bc/packages/checkpoint/data_stream/firewall/_dev/test/pipeline/test-checkpoint.log) |
| `elastic-iptables.log` | iptables : pare-feu Linux | 27 | [origine](https://raw.githubusercontent.com/elastic/integrations/354ff4c940c3bbd6fcc709d9767bd5a9e12a22bc/packages/iptables/data_stream/log/_dev/test/pipeline/test-iptables-raw.log) |

## Provenance et limites

Les versions sont figées par commit. Le manifeste local indique les URL exactes, tailles et SHA-256. Les octets des fichiers sont conservés sans réécriture ; les nombres ci-dessus comptent les lignes UTF-8 non vides.

Loghub publie des logs collectés sur des systèmes, pas nécessairement anonymisés. Sa licence prévoit la recherche ou le travail académique avec attribution et conservation de la notice. La notice complète est jointe aux fichiers dans le dossier ignoré. Source : [Loghub](https://github.com/logpai/loghub).

Les quatre fichiers Elastic sont des fixtures de test de formats et non des captures certifiées d’incidents réels. Ils proviennent uniquement des formats dev de privasoc, pas du holdout. Licence ELv2, copie locale de la licence jointe. Ne jamais les envoyer à un modèle externe (PD19). Pour cette session, tous les échantillons sont réservés aux traitements locaux.

Ce jeu sert à vérifier collecte, parsing et triage manuel. Il n’est ni étiqueté pour les attaques ni ajouté au banc P0 : aucune exactitude de détection n’en est déduite.

## Import manuel sous Windows

Depuis le dépôt `privasoc`, les commandes utilisées correspondent aux imports suivants. Ils sont déjà effectués sur la base locale :

```powershell
.\.venv\Scripts\privasoc.exe import .\data\samples-manual\2026-10-07\elastic-apache-access.log --source sample-apache-access
.\.venv\Scripts\privasoc.exe import .\data\samples-manual\2026-10-07\elastic-nginx-access.log --source sample-nginx-access
.\.venv\Scripts\privasoc.exe import .\data\samples-manual\2026-10-07\loghub-openssh.log --source sample-ssh
.\.venv\Scripts\privasoc.exe import .\data\samples-manual\2026-10-07\loghub-linux.log --source sample-linux
.\.venv\Scripts\privasoc.exe import .\data\samples-manual\2026-10-07\loghub-apache-error.log --source sample-apache-error
.\.venv\Scripts\privasoc.exe import .\data\samples-manual\2026-10-07\elastic-checkpoint.log --source sample-checkpoint
.\.venv\Scripts\privasoc.exe import .\data\samples-manual\2026-10-07\elastic-iptables.log --source sample-iptables
```

L’import est une action d’administration : il approuve cet émetteur fictif, puis cherche un parseur connu. Si le format est inconnu, les lignes restent en quarantaine et le CLI indique la prochaine action. Exécuter les commandes une par une et suivre le résultat dans Hosts, Events et Quarantine. Ne pas recopier ces fichiers dans `data/inbox/`, ni relancer un import sans vérifier ce qui est déjà chargé, pour éviter des doublons.

Après normalisation, lancer la détection depuis l’interface ou le CLI ; les dates historiques des logs doivent être prises en compte dans les recherches et corrélations.

## Test automatique effectué le 2026-10-07

Protocole : import local équivalent au CLI, un émetteur fictif par fichier, approbation
des sept émetteurs autorisée par la demande d’import, recherche du parseur intégré et
rattrapage de la quarantaine. Vérification des comptes directement dans SQLite et des
pages Hosts et Parsers authentifiées (réponses HTTP 200). Les fichiers n’ont pas été
placés dans le dossier d’ingestion automatique de Vector et aucun deuxième import n’a été lancé.

| Source | Événements normalisés | Lignes en quarantaine |
|---|---|---|
| `sample-nginx-access` | 13 | 1 |
| `sample-apache-access` | 0 | 17 |
| `sample-ssh` | 0 | 2 000 |
| `sample-linux` | 0 | 2 000 |
| `sample-apache-error` | 0 | 2 000 |
| `sample-checkpoint` | 0 | 53 |
| `sample-iptables` | 0 | 27 |
| **Total** | **13** | **6 098** |

Le format Nginx est reconnu par le parseur intégré `apache_combined`. Les autres
formats sont inconnus des parseurs intégrés actuels. Les sept fichiers ont été vérifiés
comme des lignes de logs, sans enveloppe JSON à retirer.

Essai supplémentaire sur les six sources inconnues : `qwen3:8b` local, mode structuré,
au plus deux tentatives par source, repli distant désactivé. Les six résultats sont

eeds_escalation`, aucun nouveau parseur proposé ou activé. Les rapports détaillés
restent dans le dossier ignoré : `ingestion-report.json`, `state-report.json` et
`parser-test-report.json`. Les nombres de lignes et les états de parseurs ne sont pas
une mesure d’exactitude ; ce corpus n’a pas de vérité terrain d’attaque.

La détection a été lancée et la table des alertes vérifiée : aucune alerte pour ces
sources au moment du contrôle. Cela ne prouve pas l’absence de menaces, car la plupart
des lignes ne sont pas encore normalisées. Prochaine étape : examiner les échecs de
parsing dans [Parsers](http://127.0.0.1:8000/ui/parsers?status=needs_escalation), puis
retenter ou améliorer un parseur local. L’import ne doit pas être répété sur la même base.

## Reprise du parsing le 2026-10-07

Les résultats ci-dessus décrivent le premier essai. Après correction D61/I46, seuls
les enregistrements déjà en quarantaine ont été retraités, sans réimport des fichiers.

| Source | Événements | Quarantaine |
|---|---|---|
| sample-apache-access | 17 | 0 |
| sample-apache-error | 2 000 | 0 |
| sample-nginx-access | 13 | 1 |
| sample-linux | 0 | 2 000 |
| sample-ssh | 0 | 2 000 |
| sample-checkpoint | 0 | 53 |
| sample-iptables | 0 | 27 |
| Total | 2 030 | 4 081 |

Deux parseurs fixes couvrent les variantes Apache. Le modèle reçoit désormais la
cause exacte et la position des erreurs YAML. Quatre essais locaux supplémentaires,
au plus cinq tentatives chacun : Linux proposé, trois autres toujours en échec.
Les échecs iptables sont désormais de validation ECS ; Check Point épuise cinq
tentatives ; SSH stagne sur les formes non couvertes.

Linux `93602e98` reste non activé. Un contrôle séparé des 100 premières lignes réelles
en quarantaine passe compilation, validation ECS et ancrage (100 sorties, aucune
valeur non ancrée). La proposition conserve surtout l’en-tête et le message, elle ne
prouve pas une extraction complète des événements de sécurité. La couverture de
formes de 100 % porte sur les 500 lignes du contrôle de génération, pas une précision
de champs. Revue [du parseur](http://127.0.0.1:8000/ui/parser?id=93602e98) avant approbation
explicite (privasoc D23). Les rapports détaillés `parsing-retest.json` et
`linux-review.json` restent dans le dossier ignoré. Aucun modèle externe utilisé.


Contrôle final : sept alertes de santé des sources de test, zéro alerte Sigma. API et revue Linux authentifiée accessibles après redémarrage. Les 205 tests source passent avec Vector ; Ruff et Gitleaks passent. Commit local `da0351d`.

## Extraction Linux enrichie, conservée en revue

L’opérateur a demandé de garder Linux en revue et d’améliorer son extraction.
Nouveau [candidat 90198064](http://127.0.0.1:8000/ui/parser?id=90198064), non activé,
issu de l’exemple structuré `examples/linux-system.yaml` (privasoc D62/I48).

Contrôle local sur les **2 000 lignes** déjà en quarantaine : 2 000 sorties,
aucune erreur ECS ou valeur non ancrée. Comptes de présence : processus
2000, PID 1849, IP source 1211, utilisateur
620, résultat d’événement 609. Les 236
corps non classés restent comme messages, sans résultat inventé. Ce protocole ne
mesure pas la justesse des champs face à une vérité terrain. Les horodatages syslog
sans année utilisent l’année courante, pas nécessairement l’année historique.

Résultats détaillés dans `linux-extraction-review.json` ignoré. Aucune activation,
aucun deuxième import, aucun appel modèle pour cette amélioration manuelle.
Les comptes de la base restent 2 030 événements et 4 081 lignes en quarantaine.
