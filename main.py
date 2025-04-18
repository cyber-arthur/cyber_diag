import argparse
import json
from dotenv import load_dotenv
import os

from utils.dns_tools import dns_lookup
from utils.hunter import hunter_search
from utils.osint import osint_harvester
from utils.scanner import nmap_scan, shodan_scan
from utils.exporter import export_txt

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY")

def cyber_diag(nom_entreprise: str, siren: str, ip_list: list):
    print(f"📡 Diagnostic pour {nom_entreprise} ({siren})...")
    resultats = {
        "entreprise": nom_entreprise,
        "siren": siren,
        "resultats": {
            "ips": {},
            "dns": dns_lookup(nom_entreprise),
            "osint": osint_harvester(nom_entreprise),
            "emails": hunter_search(nom_entreprise, HUNTER_API_KEY)
        }
    }

    for ip in ip_list:
        print(f"➡️ Scan IP {ip}...")
        resultats["resultats"]["ips"][ip] = {
            "nmap": nmap_scan(ip),
            "shodan": shodan_scan(ip, SHODAN_API_KEY)
        }

    output_file = f"diag_{siren}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)

    export_pdf(resultats, siren)
    print(f"\n✅ Rapport JSON généré : {output_file}")
    return resultats

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outil de diagnostic cybersécurité")
    parser.add_argument("--nom", required=True, help="Nom de domaine de l'entreprise (ex: entreprise.fr)")
    parser.add_argument("--siren", required=True, help="SIREN de l'entreprise")
    parser.add_argument("--ips", required=True, nargs="+", help="Liste des IP publiques à analyser")

    args = parser.parse_args()
    cyber_diag(args.nom, args.siren, args.ips)
