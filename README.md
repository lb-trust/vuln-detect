# Wazuh Vulnerability Reporter

Outil en ligne de commande qui exporte l'inventaire des vulnérabilités détectées par Wazuh, regroupable par poste et paquet. La première version est **en lecture seule** : elle ne modifie ni les agents ni les paquets.

> **État :** première version fonctionnelle. Les appels à l'API sont testés avec des réponses simulées ; une connexion à un environnement Wazuh réel reste à valider.

## Architecture Wazuh

Dans les versions récentes de Wazuh, les résultats du module Vulnerability Detection sont consultables dans l'index `wazuh-states-vulnerabilities-*` du **Wazuh Indexer**. L'API REST du Manager sert à administrer le Manager et les agents, mais ne fournit pas ces documents dans sa spécification actuelle.

Le programme se connecte donc directement à l'API REST de l'Indexer, généralement sur `https://<hôte>:9200`, avec un compte autorisé à lire cet index. Il récupère les résultats par pages via l'API Scroll, puis écrit un rapport CSV ou JSON. Aucun nom de service ou numéro de version correctif n'est inventé : le rapport reprend la condition d'affectation fournie par Wazuh.

Cette première version cible **Wazuh 4.14.10**, qui correspond à la version indiquée pour l'installation. Le comportement est fondé sur la documentation et les exemples de documents de cette version ; il reste à valider avec les identifiants et droits de l'Indexer de l'environnement réel.

## Informations exportées

Chaque ligne représente une vulnérabilité détectée pour un paquet sur un agent.

| Champ | Source Wazuh |
| --- | --- |
| `agent_id`, `agent_name` | Agent |
| `operating_system` | Système d'exploitation détecté |
| `package_name`, `package_version`, `package_type` | Paquet installé |
| `cve` | Identifiant CVE |
| `severity`, `cvss_score` | Gravité et score lorsqu'ils sont disponibles |
| `description` | Description de la vulnérabilité |
| `affected_condition` | Condition d'affectation renvoyée par Wazuh |
| `reference` | Référence CTI ou autre référence disponible |
| `detected_at`, `status` | Date de détection et état, si présents dans le document |

Wazuh ne fournit pas nécessairement une version corrigée dans l'inventaire. La condition d'affectation n'est pas interprétée comme une recommandation de mise à jour : confirmer la version cible auprès du fournisseur du paquet avant toute action.

## Arborescence

```text
vuln-detect/
├── README.md
├── LICENSE
├── .env.example
├── .gitignore
├── pyproject.toml
├── src/
│   └── vuln_detect/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py       # Interface en ligne de commande
│       ├── client.py    # Connexion et lecture paginée de l'Indexer
│       ├── config.py    # Configuration par variables d'environnement
│       ├── models.py    # Normalisation des documents de vulnérabilité
│       ├── report.py    # Export CSV et JSON
│       └── setup.py     # Assistant de configuration interactif
└── tests/
    ├── test_client.py
    ├── test_config.py
    └── test_report.py
```

Le client utilise uniquement la bibliothèque standard de Python.

## Prérequis

- Python 3.10 ou plus récent.
- Accès réseau à l'API REST du Wazuh Indexer.
- Un compte Indexer dédié, autorisé en lecture sur `wazuh-states-vulnerabilities-*`.
- Une chaîne de certificats TLS approuvée par la machine d'exécution.

## Installation

Ouvrir PowerShell dans le dossier du projet et exécuter :

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
```

**Aucun script PowerShell n'est exécuté et il n'est pas nécessaire d'activer l'environnement virtuel.** Chaque commande appelle directement `.\.venv\Scripts\python.exe`. Il n'est donc pas nécessaire de modifier la stratégie d'exécution PowerShell.

## Première configuration (assistant questions-réponses)

Lancer l'assistant une seule fois :

```powershell
& .\.venv\Scripts\python.exe -m vuln_detect configure
```

L'assistant pose les questions suivantes et enregistre les réponses dans le fichier local `.env` :

| Question | Quoi saisir ? | Exemple |
| --- | --- | --- |
| URL de l'API Indexer | Adresse réseau de l'Indexer, avec le protocole et le port. Ne pas saisir l'URL du Manager ni son port API `55000`. | `https://wazuh.example.net:9200` |
| Nom du compte Indexer en lecture | Compte autorisé à lire l'index Wazuh `wazuh-states-vulnerabilities-*`. Demander ce compte à l'administrateur Wazuh si nécessaire. | `vuln-reporter` |
| Mot de passe Indexer | Mot de passe de ce compte ; la saisie est masquée dans le terminal. | *(saisie masquée)* |
| Vérifier le certificat TLS ? | Répondre `oui` dans un environnement normal. | `oui` |
| Délai d'attente en secondes | Temps maximal d'attente d'une réponse Indexer. Appuyer sur Entrée pour conserver 30 secondes. | `30` |

Exemple de dialogue :

```text
Configuration de l'accès en lecture au Wazuh Indexer.
Utilisez l'adresse de l'Indexer, pas celle du Wazuh Manager.
Exemple : https://wazuh.example.net:9200
URL de l'API Indexer: https://wazuh.example.net:9200
Nom du compte Indexer en lecture: vuln-reporter
Mot de passe Indexer (saisie masquée):
Vérifier le certificat TLS ? (oui/non) [oui]:
Délai d'attente en secondes [30]:
Configuration enregistrée dans .env.
Pour lancer l'export : .\.venv\Scripts\python.exe -m vuln_detect
```

Le compte Indexer doit être configuré par l'administrateur Wazuh avec des droits **en lecture seule** sur l'index `wazuh-states-vulnerabilities-*`. Si tu ne connais pas l'URL, le compte ou ses droits, demande-les à la personne qui administre Wazuh ; ce ne sont pas les identifiants de l'API Manager. Si l'accès est en HTTPS avec un certificat interne, la machine exécutant le programme doit faire confiance à l'autorité qui l'a émis. Ne répondre `non` à la vérification TLS que pour un test contrôlé.

L'assistant ne remplace pas `.env` sans confirmation. Le fichier contient le mot de passe en clair : il est ignoré par Git, mais reste lisible par les utilisateurs qui ont accès à ton compte Windows. Ne le partage pas et préfère un gestionnaire de secrets en production.

## Utilisation

Une fois l'assistant terminé, exporter l'inventaire en CSV :

```powershell
& .\.venv\Scripts\python.exe -m vuln_detect
```

Le fichier est créé ici : `reports\vulnerabilities.csv`. Chaque ligne contient une vulnérabilité pour un paquet sur un agent. Le dossier `reports` est créé automatiquement et ses fichiers sont ignorés par Git.

Pour exporter en JSON :

```powershell
& .\.venv\Scripts\python.exe -m vuln_detect --format json --output reports\vulnerabilities.json
```

Pour enregistrer le CSV ailleurs :

```powershell
& .\.venv\Scripts\python.exe -m vuln_detect --output "C:\Users\moi\Desktop\vulnerabilities.csv"
```

L'option `--log-level DEBUG` augmente la verbosité. Le programme retourne un code non nul et affiche une erreur explicite si la configuration, l'API ou l'export échoue. Il ne journalise pas les identifiants.

### Options

| Option | Valeur par défaut | Description |
| --- | --- | --- |
| `--format` | `csv` | Format de sortie : `csv` ou `json` |
| `--output` | `reports/vulnerabilities.csv` | Chemin du fichier de sortie |
| `--log-level` | `INFO` | Niveau de journalisation |

## Configuration

En usage normal, les paramètres sont chargés depuis `.env` créé par l'assistant ; il n'est pas nécessaire de modifier des variables à la main. Le tableau ci-dessous sert de référence ou si tu préfères configurer l'environnement toi-même.

| Variable | Obligatoire | Valeur par défaut | Description |
| --- | --- | --- | --- |
| `WAZUH_INDEXER_URL` | Oui | — | URL Indexer en `http://` ou `https://`, généralement port `9200` |
| `WAZUH_INDEXER_USERNAME` | Oui | — | Nom du compte en lecture de l'Indexer |
| `WAZUH_INDEXER_PASSWORD` | Oui | — | Mot de passe correspondant |
| `WAZUH_VERIFY_TLS` | Non | `true` | Vérification du certificat HTTPS : `true` ou `false` |
| `WAZUH_TIMEOUT` | Non | `30` | Délai maximal d'une requête, en secondes |

Les variables déjà définies dans l'environnement PowerShell sont prioritaires sur celles du fichier `.env`. La désactivation de TLS (`WAZUH_VERIFY_TLS=false`) n'est prévue que pour un environnement de test contrôlé ; ne l'utilise pas pour contourner durablement un problème de certificat.

## Tests

Les tests sont indépendants d'un Manager/Indexer réel :

```powershell
$env:PYTHONPATH = "src"
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Sécurité et limites

- Utiliser un compte Indexer dédié, à privilèges minimaux et en lecture seule sur l'index ciblé.
- Protéger les identifiants et ne jamais les placer dans le dépôt ou les journaux.
- Garder la validation TLS activée et limiter l'accès réseau à l'Indexer.
- Les données reflètent l'état de l'inventaire Wazuh au moment de la collecte ; la fraîcheur dépend des synchronisations des agents.
- Le rapport aide à prioriser l'analyse ; il ne détermine pas automatiquement les paquets à installer et n'effectue aucune mise à jour.
- La version actuelle exporte l'ensemble des documents retournés par l'index ciblé. Le filtrage par groupes, agents ou sévérité pourra être ajouté dans une prochaine étape.

## Prochaines étapes

1. Confirmer la version de Wazuh, l'URL de l'Indexer et les droits du compte de lecture.
2. Tester le client sur un environnement non sensible et valider les champs présents dans les documents réels.
3. Ajouter, si besoin, des filtres d'agents, groupes ou sévérité.
4. Définir comment rapprocher les conditions Wazuh des recommandations de mise à jour validées par les équipes système.

## Références

- [Wazuh — Vulnerability Detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html)
- [Wazuh — Viewing vulnerability data](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html#viewing-vulnerability-data)
- [Wazuh — Server API reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)

## Licence

Ce projet est distribué sous licence GNU GPL version 3. Voir le fichier [LICENSE](LICENSE).
