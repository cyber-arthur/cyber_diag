# CyberDiag : outil de diagnostic cybersécurité

CyberDiag est un outil Python permettant d'effectuer un diagnostic rapide sur une entreprise en analysant son domaine, ses adresses IP publiques et ses informations exposées.

## Fonctionnalités

- 🔍 Scan IP avec **Nmap** et **Shodan**
- 🌐 Recherche **DNS** (A, MX, NS, TXT, etc.)
- 🕵️ OSINT via **theHarvester**
- 📬 Emails collectés avec **Hunter.io**
- 🧾 Enrichissement entreprise via **API SIRENE**
- 📄 Export des résultats en **JSON** et **PDF**

## Installation
```bash
chmod +x install.sh
./install.sh
```

## Utilisation

```bash
python main.py --nom entreprise.fr --siren 123456789 --ips 192.0.2.1 203.0.113.5
```

## Résultats
Lorsque le script a terminé, un dossier `resultats` est crée où se trouvent 2 fichiers : 
- `diag_<SIREN>.json` : Résultat complet au format JSON
- `diag_<SIREN>.pdf` : Rapport au format PDF 

## Sécurité et licence

🛑 **Ce projet est propriétaire. Toute réutilisation, reproduction ou diffusion est interdite sans l'accord écrite de l'auteur.**

Contact : arthur.nguyen@cyberses.fr
