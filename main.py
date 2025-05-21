import argparse
import json
import os
from dotenv import load_dotenv

from utils.dns_tools import dns_lookup
from utils.hunter import hunter_search
from utils.osint import osint_harvester
from utils.scanner import nmap_scan, shodan_scan
from utils.osint_advanced import VirusTotalClient
from utils.exporter import export_pdf

# Chargement des clés d'API
load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("Il faut définir VT_API_KEY dans votre .env")

# Instanciation du client VirusTotal
vt_client = VirusTotalClient(VT_API_KEY)

OUTPUT_DIR = "rapports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def cyber_diag(nom_entreprise: str, siren: str, ip_list: list):
    print(f"📡 Diagnostic pour {nom_entreprise} ({siren})...")
    resultats = {
        "entreprise": nom_entreprise,
        "siren": siren,
        "resultats": {
            "ips": {},
            "dns": dns_lookup(nom_entreprise),
            "osint": osint_harvester(nom_entreprise),
            "emails": hunter_search(nom_entreprise, HUNTER_API_KEY),
            # Utilisation du nouveau client VT
            "virustotal": vt_client.check_domain(nom_entreprise)
        }
    }

    for ip in ip_list:
        print(f"➡️ Scan IP {ip}...")
        resultats["resultats"]["ips"][ip] = {
            "nmap": nmap_scan(ip),
            "shodan": shodan_scan(ip, SHODAN_API_KEY),
        }

    output_file = os.path.join(OUTPUT_DIR, f"diag_{siren}.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)

    export_pdf(resultats, siren, OUTPUT_DIR)
    print(f"✅ Rapport JSON généré : {output_file}")
    return resultats

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outil de diagnostic cybersécurité")
    parser.add_argument("--nom",    required=True, help="Nom de domaine de l'entreprise (ex: entreprise.fr)")
    parser.add_argument("--siren",  required=True, help="SIREN de l'entreprise")
    parser.add_argument("--ips",    required=True, nargs="+", help="Liste des IP publiques à analyser")

    args = parser.parse_args()
    cyber_diag(args.nom, args.siren, args.ips)