import argparse
import json
import random
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

from utils.dns_tools import dns_lookup
from utils.hunter import hunter_search, enrich_emails
from utils.osint import osint_harvester
from utils.scanner import nmap_scan
from utils.osint_advanced import VirusTotalClient, OSINTClient
from utils.scraper import SiteScraper
from utils.exporter import export_pdf
from utils.pappers import fetch_pappers_data  # Appel API Pappers

# Nettoie le nom de domaine pour normalisation
def normalize_domain(domain_input: str) -> str:
    if "://" not in domain_input:
        domain_input = "https://" + domain_input
    parsed = urlparse(domain_input)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc.rstrip("/")

def run_multiple_domains(domains: list[str], siren: str, ip_list: list, api_keys: dict, use_pappers: bool):
    grouped_results = []
    for domain in domains:
        print(f"Traitement de {domain} …")
        result = cyber_diag(domain, siren, ip_list, api_keys, use_pappers, return_results=True)
        grouped_results.append((domain, result))
    return grouped_results

# Charge les clés API depuis le fichier .env
def load_api_keys() -> dict:
    load_dotenv()
    keys = {
        "HUNTER_API_KEY": os.getenv("HUNTER_API_KEY"),
        "VT_API_KEY": os.getenv("VT_API_KEY"),
        "PAPPERS_API_KEY": os.getenv("PAPPERS_API_KEY")
    }

    missing = [k for k, v in keys.items() if not v and "OPTIONAL" not in k]
    if missing:
        raise RuntimeError(f"Clés API manquantes : {', '.join(missing)}")
    return keys

# Fonction principale de diagnostic
def cyber_diag(domain: str, siren: str, ip_list: list, api_keys: dict, use_pappers: bool, return_results: bool = False):
    print(f"Début du diagnostic pour le domaine « {domain} » avec SIREN {siren}…")
    vt_client = VirusTotalClient(api_keys["VT_API_KEY"])
    osint_client = OSINTClient(vt_client)

    resultats = {
        "siren": siren,
        "resultats": {}
    }

    if use_pappers:
        print("Récupération des informations légales via Pappers…")
        pappers_data = fetch_pappers_data(siren)
        resultats["pappers"] = pappers_data or {}
    else:
        print("API Pappers désactivée par l'utilisateur.")

    # Analyse du domaine
    domaine_result = {
        "ips": {},
        "dns": dns_lookup(domain),
        "osint": osint_harvester(domain),
        "emails": hunter_search(domain, api_keys["HUNTER_API_KEY"]),
        "virustotal": osint_client.check_domain(domain)
    }

    # WHOIS enrichi
    vt_data = domaine_result["virustotal"]
    domaine_result["virustotal"]["whois"] = {
        "registrar":       vt_data.get("whois_registrar", "N/A"),
        "creation_date":   vt_data.get("whois_creation_date", "N/A"),
        "expiration_date": vt_data.get("whois_expiration_date", "N/A"),
        "owner":           vt_data.get("whois_registrar", "N/A"),
        "name_servers":    vt_data.get("whois_name_servers", [])
    }

    # Scraping
    print("Scraping du site web…")
    scraper = SiteScraper(domain, max_pages=20)
    scraping = scraper.scrape()
    scraped_emails = scraping.get("emails", [])
    enriched = enrich_emails(scraped_emails)

    hunter_emails = domaine_result["emails"]
    hunter_dict = {e["email"]: e for e in hunter_emails}
    for e in enriched:
        email = e["email"]
        if email in hunter_dict:
            hunter_dict[email]["source"] = list(set(hunter_dict[email].get("source", []) + e.get("source", [])))
        else:
            hunter_dict[email] = e
    domaine_result["emails"] = list(hunter_dict.values())
    domaine_result["scraping"] = scraping

    # IP scanning
    if ip_list:
        for ip in ip_list:
            print(f"Scan IP {ip}…")
            domaine_result["ips"][ip] = {
                "nmap": nmap_scan(ip)
            }
    else:
        print("ℹ Aucune IP fournie → aucun scan réseau effectué.")
    
        # Retourne le résultat pour ce domaine
    return {
        "pappers": resultats.get("pappers", {}),
        "virustotal": domaine_result["virustotal"],
        "emails": domaine_result["emails"],
        "dns": domaine_result["dns"],
        "ips": domaine_result["ips"],
        "osint": domaine_result["osint"],
        "scraping": domaine_result["scraping"]
    }

# Interface ligne de commande
def main():
    parser = argparse.ArgumentParser(description="Outil de diagnostic cybersécurité")
    parser.add_argument("--nom", required=True, nargs="+", help="Nom(s) de domaine à analyser")
    parser.add_argument("--siren", required=False, help="SIREN de l'entreprise (9 chiffres)")
    parser.add_argument("--ips", nargs="+", required=False, help="Liste des IP publiques à analyser.")
    parser.add_argument("--use-pappers", action="store_true", help="Inclure les données légales via l'API Pappers")
    args = parser.parse_args()

    domains = [normalize_domain(d) for d in args.nom]
    siren = args.siren if args.siren else str(random.randint(10**8, 10**9 - 1))
    if not args.siren:
        print(f"Aucun SIREN fourni → génération aléatoire : {siren}")
    ip_list = args.ips or []
    use_pappers = args.use_pappers

    api_keys = load_api_keys()
    
    grouped_results = []
    for domain in domains:
        print(f"\n Lancement analyse de {domain}")
        result = cyber_diag(domain, siren, ip_list, api_keys, use_pappers, return_results=True)
        grouped_results.append((domain, result))

    # Sauvegarde après toutes les analyses
    OUTPUT_DIR = "rapports"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    json_path = os.path.join(OUTPUT_DIR, f"diag_{siren}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({d: r for d, r in grouped_results}, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n Rapport JSON généré : {json_path}")
    export_pdf(grouped_results, siren, OUTPUT_DIR)

# Lancement
if __name__ == "__main__":
    main()
