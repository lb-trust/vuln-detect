# Wazuh Vulnerability Reporter

> **État du projet :** fondation documentaire — le script et les modules décrits ci-dessous restent à implémenter.

## Objectif

Ce projet a pour but d'interroger l'API REST du **Wazuh Manager** afin de récupérer les vulnérabilités détectées sur les agents supervisés, puis de produire un rapport exploitable indiquant, pour chaque poste, les paquets ou logiciels à mettre à jour.

Le périmètre initial est la **lecture et le reporting** : le projet ne modifie pas les postes et ne lance pas de mises à jour.

## Fonctionnement prévu

1. Se connecter à l'API REST du Wazuh Manager avec un compte dédié.
2. Récupérer les vulnérabilités pour les agents concernés, en gérant la pagination et les erreurs API.
3. Normaliser les informations retournées : poste, système, paquet/logiciel, version installée, CVE, sévérité et version corrigée lorsqu'elle est disponible.
4. Regrouper les résultats par poste et par paquet.
5. Générer un rapport, d'abord en CSV et/ou JSON, afin de faciliter le tri et le suivi des mises à jour.

Les routes, champs disponibles et méthodes de pagination dépendent de la version de Wazuh. L'implémentation devra s'appuyer sur la documentation de l'API correspondant à la version installée et vérifier notamment la route de consultation des vulnérabilités.

## Informations attendues dans un rapport

| Champ | Description |
| --- | --- |
| Agent | Nom et identifiant de l'agent Wazuh |
| Système | Système d'exploitation ou plateforme détectée |
| Paquet / logiciel | Composant vulnérable identifié par Wazuh |
| Version installée | Version observée sur le poste |
| Version corrigée | Version de correction, si fournie par Wazuh |
| CVE | Identifiant(s) des vulnérabilités associées |
| Sévérité | Niveau ou score disponible dans les données Wazuh |
| État | État remonté par Wazuh, si disponible |

Une vulnérabilité sans version corrigée connue devra être signalée comme telle plutôt que de proposer une version supposée. Les correspondances entre noms de paquets et noms de services ne sont pas toujours directes : elles ne devront être indiquées que si les données permettent de les établir.

## Arborescence proposée

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
│       ├── config.py          # Configuration et validation des paramètres
│       ├── wazuh_client.py    # Authentification et appels à l'API Wazuh
│       ├── models.py          # Modèle normalisé des agents et vulnérabilités
│       ├── collector.py       # Collecte, pagination et gestion des agents
│       ├── report.py          # Génération des rapports CSV/JSON
│       └── logging_config.py # Configuration des journaux
├── tests/
│   ├── test_config.py
│   ├── test_collector.py
│   └── test_report.py
└── reports/                   # Sorties locales (à exclure de Git)
```

Cette arborescence est une proposition de départ, fondée sur Python. Elle pourra être adaptée avant l'implémentation si une autre technologie ou un autre format de rapport est retenu.

## Prérequis

- Un Wazuh Manager accessible depuis la machine qui exécutera le script.
- Un compte API Wazuh autorisé à lire les informations nécessaires.
- Python 3 et les dépendances qui seront déclarées dans `pyproject.toml`.
- Le certificat TLS de l'API, ou une autorité de certification reconnue par la machine d'exécution.

La version minimale de Python et celle de Wazuh devront être précisées en fonction de l'environnement cible.

## Configuration prévue

Les secrets ne doivent pas être enregistrés dans le code source ni dans un fichier versionné. Une configuration locale pourra utiliser des variables d'environnement :

```dotenv
WAZUH_URL=https://wazuh.example.net:55000
WAZUH_USERNAME=
WAZUH_PASSWORD=
WAZUH_VERIFY_TLS=true
```

`.env.example` ne contient que des valeurs fictives ou vides. Le fichier `.env` local devra être ignoré par Git. En production, préférer un gestionnaire de secrets ou les mécanismes sécurisés de l'environnement d'exécution.

La vérification TLS doit rester activée. Ne la désactiver qu'en environnement de test contrôlé, jamais comme contournement permanent d'un problème de certificat.

## Utilisation envisagée

Après implémentation, l'interface pourra être lancée comme un module Python :

```powershell
python -m vuln_detect
```

La commande exacte, les options (par exemple sélection des agents ou du format) et le chemin de sortie seront définis avec l'implémentation. Ce lancement est indicatif et ne fonctionne pas tant que le code correspondant n'a pas été ajouté.

## Sécurité et fiabilité

- Utiliser un compte API à privilèges minimaux, limité à la lecture nécessaire.
- Protéger les identifiants et ne jamais les écrire dans les journaux ou rapports.
- Vérifier les certificats TLS et limiter l'accès réseau à l'API Wazuh.
- Gérer explicitement les erreurs d'authentification, les délais d'attente, les erreurs API et les réponses incomplètes.
- Respecter les limites et la pagination de l'API ; ne pas supposer qu'une seule réponse contient tous les résultats.
- Conserver la provenance des informations et éviter d'inventer une version corrective ou un nom de service.
- Ne pas exécuter de mise à jour automatique dans le périmètre initial.

## Tests prévus

Les tests devront couvrir au minimum :

- la validation de la configuration, sans utiliser de véritables secrets ;
- la normalisation des réponses Wazuh représentatives ;
- la pagination et les réponses vides ;
- les erreurs API et les données manquantes ;
- la génération et le regroupement des rapports par agent et paquet.

Les tests du client API devront utiliser des réponses simulées afin de ne pas dépendre d'un Manager réel.

## Prochaines étapes

1. Confirmer les versions de Wazuh et de Python à cibler.
2. Définir les agents à inclure (tous, actifs seulement, groupes ou liste explicite).
3. Vérifier les champs réellement renvoyés par l'API de l'installation cible, notamment la version corrigée et la sévérité.
4. Choisir le format initial du rapport et sa destination.
5. Implémenter le client API, la collecte paginée, la normalisation et les tests.

## Licence

Ce projet est distribué sous licence GNU GPL version 3. Voir le fichier [LICENSE](LICENSE).
