import argparse
import json
import random
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

from utils.dns_tools import dns_lookup
from utils.hunter import hunter_search, enrich_emails
from utils.osint import osint_harvester
from utils.scanner import nmap_scan, shodan_scan
from utils.osint_advanced import VirusTotalClient, OSINTClient
from utils.scraper import SiteScraper
from utils.exporter import export_pdf
from utils.pappers import fetch_pappers_data  # ✅ ajout ici


def normalize_domain(domain_input: str) -> str:
    if "://" not in domain_input:
        domain_input = "https://" + domain_input
    parsed = urlparse(domain_input)
    netloc = parsed.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc.rstrip("/")


def load_api_keys() -> dict:
    load_dotenv()
    keys = {
        "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY"),
        "HUNTER_API_KEY": os.getenv("HUNTER_API_KEY"),
        "VT_API_KEY": os.getenv("VT_API_KEY"),
        "PAPPERS_API_KEY": os.getenv("PAPPERS_API_KEY")  # ✅ ajout Pappers
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

    # WHOIS enrichi
    vt_data = resultats["resultats"]["virustotal"]
    resultats["resultats"]["virustotal"]["whois"] = {
        "registrar":       vt_data.get("whois_registrar", "N/A"),
        "creation_date":   vt_data.get("whois_creation_date", "N/A"),
        "expiration_date": vt_data.get("whois_expiration_date", "N/A"),
        "owner":           vt_data.get("whois_registrar", "N/A"),
        "name_servers":    vt_data.get("whois_name_servers", [])
    }

    # ✅ Appel API Pappers
    print("🏛️ Récupération des informations légales via Pappers…")
    pappers_data = fetch_pappers_data(siren)
    resultats["resultats"]["pappers"] = pappers_data or {}

    print("🌐 Scraping du site web…")
    scraper = SiteScraper(domain, max_pages=20)
    scraping = scraper.scrape()
    scraped_emails = scraping.get("emails", [])
    enriched = enrich_emails(scraped_emails)

    # Fusion emails Hunter + Scraper
    hunter_emails = resultats["resultats"]["emails"]
    hunter_dict = {e["email"]: e for e in hunter_emails}
    for e in enriched:
        email = e["email"]
        if email in hunter_dict:
            hunter_dict[email]["source"] = list(set(hunter_dict[email].get("source", []) + e.get("source", [])))
        else:
            hunter_dict[email] = e
    resultats["resultats"]["emails"] = list(hunter_dict.values())
    resultats["resultats"]["scraping"] = scraping

    if ip_list:
        for ip in ip_list:
            print(f"➡️ Scan IP {ip}…")
            resultats["resultats"]["ips"][ip] = {
                "nmap": nmap_scan(ip),
                "shodan": shodan_scan(ip, api_keys["SHODAN_API_KEY"])
            }
    else:
        print("ℹ️ Aucune IP fournie → aucun scan réseau effectué.")

    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "rapports")

    json_path = os.path.join(OUTPUT_DIR, f"diag_{siren}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False, default=str)

    print(f"✅ Rapport JSON généré : {json_path}")
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
