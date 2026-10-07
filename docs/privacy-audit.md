# privasoc+ : audit de confidentialité des livrables

Date : 2026-10-07. Objet : vérifier qu'aucun livrable ne permet d'identifier ou de profiler l'auteur avant une publication dans un dépôt public anonyme (règle D43).

Revue 3 du 2026-10-07 : les nouveaux documents, tests, configurations et la source du
diagramme v3 utilisent des valeurs fictives et des chemins de dépôts relatifs. Les fichiers
temporaires de vérification sont retirés à la clôture. Gitleaks passe sur les fichiers
changés ; seuls des secrets synthétiques de tests ont des exceptions précises. Le diagramme
v3 est rendu en SVG/PNG et son texte est contrôlé. Cela ne remplace pas l'audit de l'auteur
des anciens commits sovgate, toujours signalé par N21.

## Méthode

- Fichiers texte lus en entier : `README.md`, `feasibility.md`, `constraints.md`, `metrics.md`, `diagram-notes.md` (y compris le bloc mermaid de la séquence), `diagram.mmd`.
- SVG (`diagram.svg`, `sequence.svg`) : extraction du texte visible (balises retirées), puis recherche sur le contenu brut (attributs, commentaires, espaces de noms, URL).
- `diagram.png` exclu : il est rendu à partir de `diagram.mmd`, audité à la source.
- Recherches insensibles à la casse, avec variantes sans accent et partielles, par `grep` et par un script Python (adresses e-mail, IPv4, chemins, fuseaux horaires, tirets).

## Motifs recherchés

| Catégorie | Motifs (libellés génériques) |
|---|---|
| A. Identifiants directs | prénom et nom de l'auteur (avec et sans accent, forme partielle), identifiant et domaine de l'adresse e-mail, domaine personnel, nom de machine, nom d'utilisateur local, chemins de profil utilisateur et de dossiers de travail, chemins internes de la plateforme, noms de tiers liés à l'auteur |
| B. Lieu, nationalité, profil | lieu de résidence (plusieurs langues et variantes), nationalité (hors contexte réglementaire), âge, situation professionnelle, formation, démarches personnelles, infrastructure et matériel personnels de l'auteur, domaines ou TLD privés, IP hors plages de documentation ou de jetons, URL de session, adresses e-mail hors `example.*`, identités git |
| C. Profilage indirect | tutoiement ou vouvoiement révélant une situation privée (« tu », « ta », « votre », « vos », « mon », « chez l'auteur », « à la maison »), horodatages ou fuseaux révélant la machine (abréviations de fuseau, identifiants IANA, décalages UTC, dates ISO avec heure), matériel personnel (modèles de GPU ou de CPU), URL tierces contenant des jetons personnels |
| D. Typographie | tiret cadratin (et tiret demi-cadratin pour contrôle) |

Plages acceptées comme fictives : 192.168.1.0/24, 10.0.0.0/8 et 198.18.0.0/15 (jetons), 2001:db8::/32, `example.*`, `jdoe`, `laptop-01`.

## Constats

| # | Fichier : ligne | Texte | Problème | Gravité | Suite |
|---|---|---|---|---|---|
| 1 | `feasibility.md` : 5 | « lecture du code staged » | Écho du flux interne de mise à disposition des fichiers (outillage de l'auteur) | faible | corrigé |
| 2 | `metrics.md` : 136-137 | « sur le GPU de 8 Go » | L'article défini désigne une machine précise plutôt que le matériel du banc | faible | corrigé |
| 3 | `constraints.md` : 143, 172-173, 176, 178-181, 198, 386 ; `feasibility.md` : 83 | nLPD, Swiss-U.S. DPF, résidence « UE/CH », entités de documents d'affaires suisses | Accent réglementaire suisse ; justifié par le profil public de sovgate et la liste réglementaire | faible | conservé |
| 4 | `constraints.md` : 126, 144, 239, 245, 322 ; `metrics.md` : 137, 387, 414 | « homelab » | Profil de déploiement générique (« un homelab », « volume homelab »), jamais le domicile de l'auteur | faible | conservé |
| 5 | `README.md` : 56 ; `constraints.md` : 3, 5, 170, 223, 391 | date 2026-10-07 | Date de consultation des sources, sans heure ni fuseau ; nécessaire à la traçabilité | faible | conservé |
| 6 | `constraints.md` : 173, 197, 230-231, 407-411 | fournisseur de modèles cité | Uniquement comme fournisseur d'API (rétention, prix, limites), aucun lien avec l'auteur | aucune | conservé |
| 7 | `diagram-notes.md`, `sequence.svg` | `192.168.1.10`, `10.134.164.171`, `jdoe`, `laptop-01`, « Example Corp » | Valeurs fictives dans les plages autorisées | aucune | conservé |

Aucune occurrence des catégories A et D, aucune occurrence de B ou C liée à l'auteur. Les nombres à quatre groupes trouvés dans `sequence.svg` sont des coordonnées de tracé, pas des IP. Les SVG ne contiennent ni commentaire, ni métadonnée, ni URL autre que les espaces de noms W3C.

## Corrections

- `feasibility.md` : « lecture du code staged » remplacé par « lecture du code source fourni ».
- `metrics.md` : « sur le GPU de 8 Go » remplacé par « sur un GPU grand public de 8 Go ».
- Aucune modification de `diagram.mmd` ni du bloc mermaid : pas de nouveau rendu des SVG nécessaire.

## Résultat

Après correction, toutes les recherches ont été relancées : **0 constat de gravité haute ou moyenne**, 0 tiret cadratin. Les constats faibles restants (3 à 5) sont des choix assumés et sans lien avec l'auteur. Ce rapport n'utilise que des libellés génériques pour les valeurs personnelles recherchées.

Point d'attention hors périmètre : l'historique git, les métadonnées de commit et la licence du dépôt public doivent faire l'objet du même contrôle (voir `constraints.md` J1).
