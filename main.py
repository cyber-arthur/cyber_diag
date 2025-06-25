import argparse
import json
import random
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

from utils.dns_tools import dns_lookup
from utils.hunter import hunter_search
from utils.osint import osint_harvester
from utils.scanner import nmap_scan, shodan_scan
from utils.osint_advanced import VirusTotalClient, OSINTClient, get_company_director
from utils.scraper import SiteScraper
from utils.exporter import export_pdf

def normalize_domain(domain_input: str) -> str:
    if "://" not in domain_input:
        domain_input = "https://" + domain_input
    parsed = urlparse(domain_input)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc.rstrip("/")

# --- Chargement des clés d'API ---
load_dotenv()
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY")
HUNTER_API_KEY     = os.getenv("HUNTER_API_KEY")
VT_API_KEY         = os.getenv("VT_API_KEY")
PAPPERS_API_KEY    = os.getenv("PAPPERS_API_KEY")

if not VT_API_KEY:
    raise RuntimeError("Il faut définir VT_API_KEY dans votre .env")
if not PAPPERS_API_KEY:
    raise RuntimeError("Il faut définir PAPPERS_API_KEY dans votre .env")

# Instanciation des clients
vt_client    = VirusTotalClient(VT_API_KEY)
osint_client = OSINTClient(vt_client)

# Répertoire de sortie
OUTPUT_DIR = "rapports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def cyber_diag(nom_entreprise: str, siren: str, ip_list: list):
    print(f"📡 Diagnostic pour domaine « {nom_entreprise} » …")

    # 1) Collecte initiale
    resultats = {
        "entreprise": nom_entreprise,
        "siren": siren,
        "resultats": {
            "ips": {},
            "dns": dns_lookup(nom_entreprise),
            "osint": osint_harvester(nom_entreprise),
            "emails": hunter_search(nom_entreprise, HUNTER_API_KEY),
            "virustotal": osint_client.check_domain(nom_entreprise)
        }
    }

    # 2) Récupération du dirigeant via l’API Pappers
    print("👤 Recherche du dirigeant via Pappers…")
    directeur = get_company_director(siren)
    print("[DEBUG] Dirigeant récupéré :", directeur)
    resultats["dirigeant"] = directeur

    # 3) Enrichissement WHOIS
    vt_data = resultats["resultats"]["virustotal"]
    resultats["resultats"]["virustotal"]["whois"] = {
        "registrar":       vt_data.get("whois_registrar",      "N/A"),
        "creation_date":   vt_data.get("whois_creation_date", "N/A"),
        "expiration_date": vt_data.get("whois_expiration_date","N/A"),
        "owner":           vt_data.get("whois_registrar",      "N/A"),
        "name_servers":    vt_data.get("whois_name_servers",  [])
    }

    # 4) Scraping du site web
    print("🌐 Scraping du site web…")
    scraper = SiteScraper(nom_entreprise, max_pages=20)
    scraping_data = scraper.scrape()
    resultats["resultats"]["scraping"] = scraping_data

    # 5) Scans IP (si IP fournies)
    if ip_list:
        for ip in ip_list:
            print(f"➡️ Scan IP {ip}…")
            resultats["resultats"]["ips"][ip] = {
                "nmap":   nmap_scan(ip),
                "shodan": shodan_scan(ip, SHODAN_API_KEY)
            }
    else:
        print("ℹ️ Aucune IP fournie → aucun scan réseau effectué.")

    # 6) Sauvegarde JSON
    json_path = os.path.join(OUTPUT_DIR, f"diag_{siren}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False, default=str)
    print(f"✅ Rapport JSON généré : {json_path}")

    # 7) Génération PDF
    export_pdf(resultats, siren, OUTPUT_DIR)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outil de diagnostic cybersécurité")
    parser.add_argument("--nom", required=True, help="Nom de domaine de l'entreprise (ex: entreprise.fr)")
    parser.add_argument("--siren", required=False, help="SIREN de l'entreprise (9 chiffres).")
    parser.add_argument("--ips", nargs="+", required=False, help="Liste des IP publiques à analyser.")
    args = parser.parse_args()

    # Normalisation du domaine
    domain = normalize_domain(args.nom)

    # SIREN : auto-généré si non fourni
    if not args.siren:
        siren = str(random.randint(10**8, 10**9 - 1))
        print(f"Aucun SIREN fourni → génération d'un SIREN aléatoire : {siren}")
    else:
        siren = args.siren

    # IPs à scanner
    ip_list = args.ips or []
    if not ip_list:
        print("Aucune IP fournie → le scan réseau sera ignoré.")

    cyber_diag(domain, siren, ip_list)
