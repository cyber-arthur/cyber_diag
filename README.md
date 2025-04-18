# CyberDiag : outil de diagnostic cybersécurité

CyberDiag est un outil Python permettant d'effectuer un diagnostic rapide sur une entreprise en analysant son domaine, ses adresses IP publiques et ses informations exposées.

## Fonctionnalités

- 🔍 Scan IP avec **Nmap** et **Shodan**
- 🌐 Recherche **DNS** (A, MX, NS, TXT, etc.)
- 🕵️ OSINT via **theHarvester**
- 📬 Emails collectés avec **Hunter.io**
- 🧾 Enrichissement entreprise via **API SIRENE**
- 📄 Export des résultats en **JSON** et **PDF**

## Prérequis externes
1. `theHarvester` installé dans `~/theHarvester/`
```
git clone https://github.com/laramies/theHarvester.git
pip install -r requirements/base.txt
```
## Installation

1. Clonez le dépôt :
   ```bash
   git clone git@github.com:cyber-arthur/cyber_diag.git
   cd cyber_diag
   ```

2. Installez les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

3. Configurez votre fichier `.env` :
   ```env
   SHODAN_API_KEY=your_shodan_api_key
   HUNTER_API_KEY=your_hunter_api_key
   ```

## Utilisation

```bash
python main.py --nom entreprise.fr --siren 123456789 --ips 192.0.2.1 203.0.113.5
```

## Résultats

- `diag_<SIREN>.json` : Résultat complet au format JSON
- `diag_<SIREN>.pdf` : Rapport au format PDF 

## Sécurité et licence

🛑 **Ce projet est propriétaire. Toute réutilisation, reproduction ou diffusion est interdite sans l'accord écrite de l'auteur.**

Contact : arthur.nguyen@cyberses.fr
