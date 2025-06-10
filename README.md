---

# 🛡️ CyberDiag : Outil de diagnostic cybersécurité

**CyberDiag** est un outil en ligne de commande (CLI) développé en Python, conçu pour aider les professionnels comme les débutants à évaluer rapidement l’exposition en ligne d’une entreprise. Il centralise des outils de cybersécurité reconnus dans un processus automatisé et produit des rapports lisibles, en JSON et PDF.

Que vous soyez auditeur, consultant, analyste SOC, ou simplement curieux de savoir ce que révèle Internet sur un domaine, **CyberDiag** vous guide étape par étape.

---

## 🧠 Que fait CyberDiag ?

Il scanne et analyse quatre grands axes :

1. **Les informations publiques liées au nom de domaine**
2. **Les services exposés via les adresses IP publiques**
3. **Les données sensibles ou stratégiques disponibles en ligne (OSINT)**
4. **Un rapport automatique prêt à l’impression ou à l’archivage**

---

## 🔍 1. Analyse du domaine

CyberDiag interroge les bases de données et les serveurs publics pour collecter :

* **WHOIS** : informations administratives du domaine (propriétaire, registrar, dates).
* **DNS** : enregistrements essentiels (`A`, `MX`, `NS`, `TXT`, etc.).
* **Certificat SSL/TLS** : validité, autorité de certification, sujets.
* **En-têtes HTTP** : présence ou non de politiques de sécurité (HSTS, CSP, X-Frame-Options…).

🔎 *Utilité : détecter une mauvaise configuration DNS, un certificat expiré, ou un domaine mal protégé.*

---

## 🌐 2. Scan des IP publiques

Le script identifie les services visibles sur les IP fournies à l’aide de deux techniques :

* **Nmap** : pour découvrir les ports ouverts et services actifs.
* **Shodan** : une base de données mondiale d’objets connectés indexant les métadonnées visibles (OS, ports, tags, fournisseurs…).

🔎 *Utilité : repérer des services vulnérables ou exposés inutilement (ex : interface d’administration, base de données, FTP public…).*

---

## 🕵️ 3. Collecte OSINT (renseignements en sources ouvertes)

CyberDiag extrait des données sensibles laissées involontairement accessibles :

* **theHarvester** : e-mails, sous-domaines, hôtes visibles via moteurs de recherche.
* **Hunter.io** : adresses e-mail liées au domaine, avec un score de fiabilité.
* **VirusTotal v3** : réputation globale du domaine, nombre de détections malicieuses.
* **Scraping Web** : fouille des pages internes du site web à la recherche de :

  * Emails et téléphones
  * Adresses postales
  * Prénoms/Noms identifiables
  * Liens vers les réseaux sociaux professionnels

🔎 *Utilité : découvrir des informations internes exposées sans contrôle (e.g., email RH, téléphone direct du PDG, employés mentionnés).*

---

## 📝 4. Export des résultats

* **Fichier JSON** : structuré, facile à intégrer dans des outils ou des SIEM.
* **Fichier PDF** : lisible, avec couverture, sommaire, sections claires, et graphiques.

📂 Les fichiers générés sont nommés automatiquement selon le numéro SIREN, pour faciliter la traçabilité et l’archivage.

---

## 🛠️ Fonctionnalités détaillées

| Fonctionnalité   | Description                                                                        |
| ---------------- | ---------------------------------------------------------------------------------- |
| **DNS**          | Extraction des enregistrements DNS via `utils/dns_tools.py`                        |
| **OSINT passif** | theHarvester intégré via un wrapper Python                                         |
| **Hunter.io**    | Récupération + score des emails trouvés via API                                    |
| **VirusTotal**   | Requête sur la réputation et les statistiques malwares via API officielle          |
| **SSL/TLS**      | Analyse du certificat via socket & parsing X.509                                   |
| **HTTP Headers** | Inspection des politiques HTTP de sécurité (CSP, X-Frame-Options, etc.)            |
| **Scan IP**      | Combinaison de Nmap + Shodan pour une visibilité complète                          |
| **Scraper Web**  | Crawl de plusieurs pages internes pour extraire des entités spécifiques            |
| **Rapports**     | JSON brut pour l’automatisation, PDF visuel pour les réunions ou livrables clients |

---

## ⚙️ Installation simplifiée

Vous n’avez besoin que d’un terminal Linux (Debian/Ubuntu) et de quelques minutes :

```bash
sudo apt update \
  && sudo apt install -y python3 python3-venv python3-pip python3-full nmap git dnsutils \
  && git clone https://github.com/cyber-arthur/cyber_diag.git \
  && cd cyber_diag \
  && chmod +x cyber_diag.sh \
  && ./cyber_diag.sh
```

Le script `cyber_diag.sh` :

1. Crée un environnement Python virtuel (`venv`)
2. Installe toutes les bibliothèques nécessaires
3. Clone et prépare theHarvester

---

## 🧾 Configuration rapide

Créez un fichier `.env` à la racine du dossier :

```dotenv
SHODAN_API_KEY=VotreCleShodan
HUNTER_API_KEY=VotreCleHunter
VT_API_KEY=VotreCleVirusTotal
```

> ⚠️ L’absence de `VT_API_KEY` empêche le script de s’exécuter.

---

## ▶️ Utilisation pas à pas

### 1. Activez l’environnement virtuel :

```bash
source venv/bin/activate
```

### 2. Lancez l’analyse :

```bash
python main.py \
  --nom   monentreprise.fr \
  --siren 123456789 \
  --ips   192.0.2.1 203.0.113.5
```

**Paramètres :**

* `--nom` : le nom de domaine à auditer
* `--siren` : le numéro SIREN (généré automatiquement si non fourni)
* `--ips` : adresses IP publiques (par défaut : `8.8.8.8`)

### 3. Résultats dans `rapports/` :

* `diag_<SIREN>.json`
* `diag_<SIREN>.pdf`

---

## 📁 Arborescence du projet

```
CYBER_DIAG/
├─ main.py             # Orchestrateur principal
├─ cyber_diag.sh       # Script d'installation automatisé
├─ requirements.txt    # Dépendances Python
├─ README.md           # Documentation
└─ utils/
   ├─ dns_tools.py         # Résolution DNS
   ├─ exporter.py          # Export JSON + PDF + Graphiques
   ├─ helpers.py           # Fonctions diverses (formatage, shell)
   ├─ hunter.py            # Intégration Hunter.io
   ├─ osint.py             # theHarvester (wrapper)
   ├─ osint_advanced.py    # VirusTotal (API v3)
   ├─ scanner.py           # Nmap + Shodan
   └─ scraper.py           # Crawling & extraction
```

---

## 🔍 Détail des modules techniques

### `main.py`

Cœur du programme. Exécute chaque étape dans l’ordre logique.

### `utils/exporter.py`

* Génère les PDF lisibles et les graphiques
* Gère l’export JSON
* Récupère les certificats SSL et headers HTTP

### `utils/scraper.py`

* Crawle les pages internes
* Extrait noms, emails, téléphones, adresses, réseaux sociaux

---

## 🔒 Mentions légales

> 🛑 **Usage réservé à un cadre légal ou interne.**
> Toute utilisation abusive ou diffusion est interdite sans autorisation écrite.

Contact : [arthur.nguyen@cyberses.fr](mailto:arthur.nguyen@cyberses.fr)

---

> *Dernière mise à jour :* **juin 2025**
> *Fuseau horaire du rapport PDF :* **Europe/Paris**
> *Format de date/heure :* `%d %B %Y %H:%M %Z`
> *Police corporate :* **Helvetica**
> *Couleur principale :* `#003366`

---
