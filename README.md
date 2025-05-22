
# CyberDiag : outil de diagnostic cybersécurité

**CyberDiag** est un outil CLI Python qui réalise un diagnostic complet d’une entreprise en analysant :
- son **domaine** web (WHOIS, DNS, certificat SSL/TLS, en-têtes HTTP)  
- ses **adresses IP publiques** (scan Nmap, services, Shodan)  
- ses **informations exposées** (OSINT via theHarvester, Hunter.io, scraping du site web)  

Les résultats sont exportés au format **JSON** et **PDF** (mise en page corporate, fuseau Europe/Paris).

---

## 🚀 Fonctionnalités

- 🔍 **Scan IP**  
  - **Nmap** (`-sV`)  
  - **Shodan** (API)  
- 🌐 **Recherche DNS** (A, MX, NS, TXT…)  
- 🕵️‍♂️ **OSINT** passif via **theHarvester**  
- 📬 **Emails** collectés avec **Hunter.io**  
- 🛡️ **Analyse de domaine** via **VirusTotal v3** (stats, verdicts, réputation)  
- 🔒 **Certificat SSL/TLS** et **Headers HTTP**  
- 🕸️ **Scraping** du site (emails, téléphones, adresses postales, noms/prénoms, liens réseaux sociaux courts)  
- 📄 **Rapports**  
  - **JSON** structuré (`diag_<SIREN>.json`)  
  - **PDF** professionnel (`diag_<SIREN>.pdf`)  

---

## 📦 Installation

### Prérequis système

```bash
sudo apt update && sudo apt install -y \
  python3 python3-pip python3-venv python3-full \
  nmap git dnsutils
````

### Récupération du dépôt

```bash
git clone https://github.com/cyber-arthur/cyber_diag.git
cd cyber_diag
sudo chown -R $USER:$USER .
```

### Installation & initialisation

```bash
chmod +x cyber_diag.sh
./cyber_diag.sh
```

Le script va :

1. Créer et activer un environnement virtuel `venv/`
2. Installer les dépendances Python listées dans `requirements.txt`
3. Cloner `theHarvester` et installer ses dépendances

---

## 🔧 Configuration

Créez (ou mettez à jour) le fichier `.env` à la racine :

```dotenv
SHODAN_API_KEY=ta_cle_shodan
HUNTER_API_KEY=ta_cle_hunter
VT_API_KEY=ta_cle_virustotal
```

---

## 🎬 Utilisation

Activez l’environnement et lancez le diagnostic :

```bash
source venv/bin/activate
python main.py \
  --nom   entreprise.fr \
  --siren 123456789 \
  --ips   192.0.2.1 203.0.113.5
```

* `--nom`   : nom de domaine à analyser
* `--siren` : numéro SIREN de l’entreprise
* `--ips`   : liste d’adresses IP publiques

À la fin, vous trouverez dans `rapports/` :

* `diag_<SIREN>.json`
* `diag_<SIREN>.pdf`

---

## 📂 Structure du projet

```
CYBER_DIAG/
├─ main.py             # Point d’entrée CLI
├─ cyber_diag.sh       # Script d’installation et d’exécution
├─ requirements.txt    # Dépendances Python
├─ README.md           # Cette documentation
└─ utils/              # Modules utilitaires
   ├─ dns_tools.py         # Requêtes DNS
   ├─ exporter.py          # Génération JSON+PDF & graphismes
   ├─ helpers.py           # Fonctions partagées
   ├─ hunter.py            # Intégration Hunter.io
   ├─ osint.py             # Wrapper theHarvester
   ├─ osint_advanced.py    # Client VirusTotal v3
   ├─ scanner.py           # nmap_scan, shodan_scan
   └─ scraper.py           # Crawl & extraction (emails, téléphones, adresses, noms, socials)
```

---

## ⚙️ Description des modules

* **`main.py`**
  Orchestre :

  1. DNS lookup
  2. OSINT Harvester
  3. Hunter.io
  4. VirusTotal
  5. Scan IP (Nmap + Shodan)
  6. Scraping site web
  7. Sauvegarde JSON + génération PDF

* **`utils/dns_tools.py`**
  Fonctions pour interroger A, MX, NS, TXT, etc.

* **`utils/hunter.py`**
  Wrapper API Hunter.io pour récupérer les e-mails du domaine.

* **`utils/osint.py`**
  Exécution de `theHarvester` et extraction des résultats.

* **`utils/osint_advanced.py`**
  Client VirusTotal v3 (stats, verdicts, réputation, catégories).

* **`utils/scanner.py`**

  * `nmap_scan(ip)`
  * `shodan_scan(ip, api_key)`

* **`utils/scraper.py`**
  `SiteScraper` crawl jusqu’à N pages internes et extrait via regex :

  * Emails, téléphones, adresses FR
  * Noms/prénoms heuristiques
  * Liens réseaux sociaux courts

* **`utils/exporter.py`**

  * Récupération certificat TLS & headers HTTP
  * Nettoyage OSINT
  * Génération du schéma de ports (barres horizontales)
  * Classe `PDF` (FPDF) pour couverture, sommaire, sections, encodage Latin-1
  * Fonction `export_pdf()` assemble toutes les sections et crée le PDF

---

## ⚠️ Sécurité & Licence

🛑 **Usage réservé** : ce projet est **propriétaire**.
Toute reproduction, modification ou diffusion sans accord écrit est **interdite**.

Contact : [arthur.nguyen@cyberses.fr](mailto:arthur.nguyen@cyberses.fr)

```
```
