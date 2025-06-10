# CyberDiag : Outil de diagnostic cybersécurité

**CyberDiag** est un outil CLI Python qui automatise le diagnostic de la posture en ligne d’une entreprise, en combinant :

1. **Analyse du domaine**  
   - WHOIS (registrar, dates, owner)  
   - DNS (A, MX, NS, TXT…)  
   - Certificat SSL/TLS (émetteur, sujet, validité)  
   - En-têtes HTTP (HSTS, CSP, X-Frame-Options…)

2. **Scan des IP publiques**  
   - **Nmap** (`-sV -Pn -T4`) pour détection de services  
   - **Shodan** (API) pour métadonnées : OS, organisation, ports, tags

3. **Collecte d’informations exposées**  
   - **theHarvester** pour e-mails, noms d’hôtes, sous-domaines  
   - **Hunter.io** pour listes d’adresses e-mail et score de confiance  
   - **VirusTotal v3** pour réputation, statistiques de détection, verdicts  
   - **Scraping** flexible du site web (emails, téléphones, adresses, noms/prénoms, liens réseaux sociaux “courts”)

4. **Export des résultats**  
   - **JSON** structuré (`rapports/diag_<SIREN>.json`)  
   - **PDF** soigné (couverture, sommaire, sections détaillées, graphiques)  

---

## 🚀 Fonctionnalités détaillées

| Fonctionnalité              | Détail                                                                                               |
|-----------------------------|------------------------------------------------------------------------------------------------------|
| **DNS**                     | A, AAAA, MX, NS, TXT… via `utils/dns_tools.py`                                                       |
| **OSINT passif**            | theHarvester (wrapper dans `utils/osint.py`)                                                         |
| **Hunter.io**               | Recherche et scoring d’emails (`utils/hunter.py`)                                                    |
| **VirusTotal v3**           | Statistiques (malicious, suspicious, harmless), réputation (`utils/osint_advanced.py`)               |
| **Certificat SSL/TLS**      | Récupération via socket, parsing des RDN (`utils/exporter.py`)                                       |
| **Headers HTTP**            | Requête HEAD pour HSTS, CSP, X-Frame-Options…                                                         |
| **Scan IP**                 | Nmap (`utils/scanner.py`) & Shodan API                                                                |
| **Scraper**                 | Crawl jusqu’à _N_ pages internes, extrait :                                                         |
|                             | • Emails, téléphones (+ liens `tel:`)                                                                |
|                             | • Adresses postales (regex, `<address>`, microformats Schema.org, lignes avec code postal)         |
|                             | • Noms / prénoms (heuristique stricte, Maj+min, 2–3 mots)                                           |
|                             | • Liens réseaux sociaux “courts” (LinkedIn, Facebook, Instagram, Twitter)                            |
| **Rapports**                | • JSON complet, horodaté<br>• PDF avec couverture, sommaire, sections numérotées, graphiques (ports) |

---

## 📦 Installation en une seule commande

```bash
sudo apt update \
  && sudo apt install -y python3 python3-venv python3-pip python3-full nmap git dnsutils \
  && git clone https://github.com/cyber-arthur/cyber_diag.git \
  && cd cyber_diag \
  && chmod +x cyber_diag.sh \
  && ./cyber_diag.sh
````

Le script `cyber_diag.sh` :

1. **Crée** et **active** `venv/`
2. **Installe** les dépendances Python (`requirements.txt`)
3. **Clone** et configure **theHarvester**

---

## 🔧 Configuration

À la racine du projet, créez un fichier **`.env`** :

```dotenv
SHODAN_API_KEY=VotreCleShodan
HUNTER_API_KEY=VotreCleHunter
VT_API_KEY=VotreCleVirusTotal
```

> Si `VT_API_KEY` n’est pas défini, le script s’interrompt.

---

## 🎬 Utilisation

1. **Activez** l’environnement virtuel :

   ```bash
   source venv/bin/activate
   ```

2. **Lancez** le diagnostic :

   ```bash
   python main.py \
     --nom   entreprise.fr \
     --siren 123456789 \
     --ips   192.0.2.1 203.0.113.5
   ```

   * `--nom`     : domaine à analyser (ex. `monentreprise.fr`)
   * `--siren` : numéro SIREN (9 chiffres) — généré aléatoirement sinon
   * `--ips`    : liste d’IP publiques — 8.8.8.8 par défaut

3. **Consultez** le dossier `rapports/` :

   * `diag_<SIREN>.json`
   * `diag_<SIREN>.pdf`

---

## 🗂 Structure du projet

```
CYBER_DIAG/
├─ main.py             # CLI, orchestration de tous les modules
├─ cyber_diag.sh       # Installation & bootstrap (venv, deps, theHarvester)
├─ requirements.txt    # Dépendances Python
├─ README.md           # Documentation (vous y êtes !)
└─ utils/              # Modules utilitaires
   ├─ dns_tools.py         # Fonctions DNS
   ├─ exporter.py          # JSON/PDF, graphiques (FPDF + matplotlib)
   ├─ helpers.py           # Helpers shell, formatage
   ├─ hunter.py            # API Hunter.io
   ├─ osint.py             # Wrapper theHarvester
   ├─ osint_advanced.py    # Client VirusTotal v3
   ├─ scanner.py           # nmap_scan(), shodan_scan()
   └─ scraper.py           # SiteScraper (crawl & extraction)
```

---

## ⚙️ Détails des modules

### `main.py`

Orchestre le flow :

1. DNS
2. OSINT (theHarvester, Hunter)
3. VirusTotal
4. Scrans IP (Nmap + Shodan)
5. Scraping du site
6. Export JSON + PDF

### `utils/dns_tools.py`

— *dns\_lookup(domain)* : A, AAAA, MX, NS, TXT, SOA…

### `utils/hunter.py`

— *hunter\_search(domain, api\_key)* : liste d’e-mails, score de confiance

### `utils/osint.py`

— Exécution locale de `theHarvester`, récupération texte brut

### `utils/osint_advanced.py`

— Client officiel VT v3 (requêtes */domains/{domain}*)

### `utils/scanner.py`

* **nmap\_scan(ip)** : `nmap -T4 -Pn -sV`
* **shodan\_scan(ip, key)** : métadonnées host

### `utils/scraper.py`

Classe `SiteScraper(base_url, max_pages)` :

* Crawl interne (`requests` + `BeautifulSoup`)
* Regex & balises pour Emails, Téléphones, Adresses (regex/microformats/`<address>`/lignes), Noms-Prénoms, Liens sociaux courts

### `utils/exporter.py`

* **fetch\_certificate\_info(domain)** via socket + SSL
* **fetch\_http\_headers(domain)** via HEAD
* **clean\_osint\_text(text)** filtre theHarvester
* **generate\_ports\_chart(ips\_data)** (barres horizontales)
* **PDF** (FPDF) : couverture, sommaire, sections, encodage Latin-1
* **export\_pdf(resultats, siren, outdir)** assemble tout et génère `diag_<SIREN>.pdf`

---

## 🔒 Sécurité & Licence

🛑 **Usage interne & propriétaire**
Toute reproduction, modification ou diffusion sans autorisation écrite est interdite.

Contact : [arthur.nguyen@cyberses.fr](mailto:arthur.nguyen@cyberses.fr)


> _Dernière mise à jour :_ **juin 2025**  
> _Fuseau horaire du rapport PDF :_ **Europe/Paris**  
> _Format de date/heure :_ `%d %B %Y %H:%M %Z`  
> _Police corporate :_ **Helvetica**  
> _Couleurs :_ `#003366` (corporate)  

