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
from utils.papper_api import PappersClient
from utils.scraper import SiteScraper
from utils.exporter import export_pdf


def normalize_domain(domain_input: str) -> str:
    """Nettoie et extrait le nom de domaine."""
    if "://" not in domain_input:
        domain_input = "https://" + domain_input
    parsed = urlparse(domain_input)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc.rstrip("/")


def load_api_keys() -> dict:
    """Charge les clés d’API à partir du fichier .env"""
    load_dotenv()
    keys = {
        "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY"),
        "HUNTER_API_KEY": os.getenv("HUNTER_API_KEY"),
        "VT_API_KEY": os.getenv("VT_API_KEY"),
        "PAPPERS_API_KEY": os.getenv("PAPPERS_API_KEY"),
    }

    missing = [k for k, v in keys.items() if not v and "OPTIONAL" not in k]
    if missing:
        raise RuntimeError(f"Clés API manquantes : {', '.join(missing)}")

    return keys


def cyber_diag(domain: str, siren: str, ip_list: list, api_keys: dict):
    print(f"📡 Diagnostic pour domaine « {domain} » …")

    vt_client = VirusTotalClient(api_keys["VT_API_KEY"])
    osint_client = OSINTClient(vt_client)

    resultats = {
        "entreprise": domain,
        "siren": siren,
        "resultats": {
            "ips": {},
            "dns": dns_lookup(domain),
            "osint": osint_harvester(domain),
            "emails": hunter_search(domain, api_keys["HUNTER_API_KEY"]),
            "virustotal": osint_client.check_domain(domain)
        }
    }

    # Récupération du dirigeant
    print("👤 Recherche du dirigeant via Pappers…")
    directeur = get_company_director(siren)
    print("[DEBUG] Dirigeant récupéré :", directeur)
    resultats["dirigeant"] = directeur

    # WHOIS enrichi
    vt_data = resultats["resultats"]["virustotal"]
    resultats["resultats"]["virustotal"]["whois"] = {
        "registrar":       vt_data.get("whois_registrar",      "N/A"),
        "creation_date":   vt_data.get("whois_creation_date",  "N/A"),
        "expiration_date": vt_data.get("whois_expiration_date","N/A"),
        "owner":           vt_data.get("whois_registrar",      "N/A"),
        "name_servers":    vt_data.get("whois_name_servers",   [])
    }

    # Scraping
    print("🌐 Scraping du site web…")
    scraper = SiteScraper(domain, max_pages=20)
    resultats["resultats"]["scraping"] = scraper.scrape()

    # Scan IPs
    if ip_list:
        for ip in ip_list:
            print(f"➡️ Scan IP {ip}…")
            resultats["resultats"]["ips"][ip] = {
                "nmap": nmap_scan(ip),
                "shodan": shodan_scan(ip, api_keys["SHODAN_API_KEY"])
            }
    else:
        print("ℹ️ Aucune IP fournie → aucun scan réseau effectué.")

    # Sauvegarde
    OUTPUT_DIR = "rapports"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    json_path = os.path.join(OUTPUT_DIR, f"diag_{siren}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False, default=str)

    print(f"✅ Rapport JSON généré : {json_path}")

    # Export PDF
    export_pdf(resultats, siren, OUTPUT_DIR)


def main():
    parser = argparse.ArgumentParser(description="Outil de diagnostic cybersécurité")
    parser.add_argument("--nom", required=True, help="Nom de domaine de l'entreprise (ex: entreprise.fr)")
    parser.add_argument("--siren", required=False, help="SIREN de l'entreprise (9 chiffres).")
    parser.add_argument("--ips", nargs="+", required=False, help="Liste des IP publiques à analyser.")
    args = parser.parse_args()

    domain = normalize_domain(args.nom)

    siren = args.siren if args.siren else str(random.randint(10**8, 10**9 - 1))
    if not args.siren:
        print(f"Aucun SIREN fourni → génération aléatoire : {siren}")

    ip_list = args.ips or []

    api_keys = load_api_keys()
    cyber_diag(domain, siren, ip_list, api_keys)


if __name__ == "__main__":
    main()
