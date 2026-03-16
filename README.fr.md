# ADFT v1.0

ADFT est un toolkit d’investigation **offline** pour environnements Active Directory / Windows avec **GUI locale intégrée**.

Cette release officielle publie une seule surface produit cohérente :

- le moteur ADFT
- la CLI
- la GUI intégrée servie par le backend

ADFT ingère des preuves exportées, convertit toutes les sources supportées vers un format canonique JSONL, applique des détections et corrélations déterministes, calcule un score d’exposition AD observée, reconstruit la progression d’attaque et génère des artefacts d’investigation et de hardening exploitables.

## Périmètre de cette release v1.0

ADFT v1.0 supporte :

- conversion canonique JSONL
- investigation offline à partir de preuves exportées
- détections et corrélations déterministes
- reconstruction de timeline et rendu d’attack paths
- scoring d’exposition AD observée
- findings de hardening et export optionnel de scripts PowerShell
- rapports HTML, JSON et CSV
- exports ATT&CK Navigator, replay JSON, graphe Mermaid et manifeste d’intégrité
- GUI locale intégrée servie par le backend
- onglet benchmark dans la GUI pour la validation release et runtime

## Formats d’entrée supportés

- JSON / JSONL / NDJSON
- EVTX
- YAML / YML
- CSV / TSV
- CEF / LEEF
- XML
- LOG / SYSLOG / TXT
- Markdown
- ZIP

## Installation

Installation simple recommandée :

```bash
./install_adft.sh
```

Installation recommandée pour une vraie validation EVTX :

```bash
./install_adft.sh --run-demo
```

Installation manuelle :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[full]"
```

Installation développement :

```bash
pip install -e ".[full,dev]"
```

Le détail des dépendances est documenté dans `docs/DEPENDENCIES.md`.

Note dépôt : `pyproject.toml` est la source de vérité pour le packaging. `install_adft.sh` est le chemin officiel d’installation complète pour v1.0, et `requirements-dev.txt` reste disponible pour les contributeurs et la CI.

## Commandes principales

```bash
adft convert test_logs -o converted_inputs
adft investigate test_logs/attack.json -o reports_core --format html json csv --export-events-jsonl
adft summary -o reports_core
adft alerts -o reports_core --full
adft score -o reports_core
adft story -o reports_core --full
adft attack-chain -o reports_core
adft attack-path -o reports_core
adft reconstruct -o reports_core --full
adft harden -o reports_core --dry-run --export-scripts reports_core/remediation
adft report -o reports_core
```

## GUI intégrée

Lancement :

```bash
adft ui -o reports_gui --host 127.0.0.1 --port 8765
```

Puis ouvrir :

```text
http://127.0.0.1:8765
```

La GUI est pilotée par le backend : upload, conversion, investigation, alertes, timeline, reconstruction, graphe, benchmark, hardening et exports lisent l’état réel du moteur ADFT au lieu de rejouer une logique métier dans le navigateur.

### Caractéristiques GUI actuelles

- onglet navigateur et icône marqués **ADFT UI**
- assets statiques servis sans cache
- action rafraîchir reliée au backend et à ses capacités
- graphe d’entités centré avec zoom, déplacement, drag de nœuds, flèches, labels et filtre temporel
- enrichissement des nœuds avec risque, first-seen / last-seen et marquage IOC connu quand la preuve existe
- réduction du bruit via pagination max 50 nœuds affichés
- onglet benchmark pour la validation technique

## Artefacts générés

- `adft_report.html`
- `adft_report.json`
- `adft_report.csv`
- `attack_navigator_layer.json`
- `adft_replay.json`
- `attack_graph.mmd`
- `adft_integrity.json`
- `.adft_last_run.json`
- `converted_inputs/conversion_manifest.json`
- `hardening_scripts.zip` après export GUI ou CLI

## Note EVTX

EVTX reste dans le périmètre supporté.
À l’exécution, le parsing EVTX nécessite `python-evtx`.

Sans cette dépendance, une conversion EVTX ne peut pas aboutir.
La voie d’installation recommandée pour la release officielle est donc :

```bash
pip install -e ".[full]"
```

## Rulepack

Cette release embarque **34 rules** dans un pipeline déterministe et explicable.

## Structure du dépôt

```text
adft/
  cli/             points d’entrée CLI
  core/            ingestion, normalisation et modèles de données
  detection/       rulepack déterministe et pipeline de détection
  correlation/     corrélation et regroupement des signaux
  timeline/        reconstruction chronologique
  graph/           graphe d’entités et attack paths
  investigation/   narration et reconstruction de compromission
  analysis/        scoring et qualité de données
  harden/          logique de remédiation
  reporting/       rapports JSON, CSV et HTML standalone
  exports/         exports Navigator et replay
  ui_server.py     serveur HTTP intégré et pont backend GUI
  webui_dist/      assets packagés de la GUI
  datasets/        jeux de données de démo
frontend_source/
  src/             source React/Vite de la GUI intégrée
```

## Validation

```bash
pytest -q
python3 main.py investigate adft/datasets/ransomware_pre_encryption_campaign.json -o /tmp/adft_release_reports --format html json csv --export-events-jsonl
python3 main.py ui -o /tmp/adft_release_reports --host 127.0.0.1 --port 8765
```

Voir aussi :

- `docs/TESTING.md`
- `docs/ARCHITECTURE.md`
- `docs/DEPENDENCIES.md`
- `RELEASE_VALIDATION.md`

## Bascule de langue UI

La GUI intégrée inclut un switch persistant FR/EN dans la barre haute. Le choix est stocké localement dans le navigateur et s’applique à la navigation principale, aux écrans et aux libellés analyste.


## Dataset de démonstration

ADFT v1.0 embarque `adft/datasets/ad_prod_investigation_post_siem_demo_1000_events` et `adft/datasets/ad_prod_investigation_post_siem_demo_1000_events.zip` pour une démonstration bout en bout d'une attaque ransomware réaliste couvrant la conversion, la timeline, le graphe, les alertes et les exports.
