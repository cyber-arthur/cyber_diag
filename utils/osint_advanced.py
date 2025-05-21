import os
import time
import logging
from typing import Any, Dict, List, Optional

import requests
import whois
from dotenv import load_dotenv

# Chargement de la clé d'API depuis .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("Il faut définir VT_API_KEY dans votre .env")

# Config logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"
    RATE_LIMIT_SLEEP = 15

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key})

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.BASE_URL}{path}"
        resp = self.session.get(url, params=params, timeout=10)
        if resp.status_code == 429:  # rate limit
            logging.warning("Rate limit hit, sleeping %s seconds", self.RATE_LIMIT_SLEEP)
            time.sleep(self.RATE_LIMIT_SLEEP)
            return self._get(path, params)
        resp.raise_for_status()
        return resp.json()

    def domain_report(self, domain: str) -> Dict[str, Any]:
        return self._get(f"/domains/{domain}")

    def domain_analysis_stats(self, domain: str) -> Dict[str, int]:
        data = self.domain_report(domain).get("data", {}).get("attributes", {})
        return data.get("last_analysis_stats", {})

    def domain_analysis_results(self, domain: str) -> Dict[str, Any]:
        data = self.domain_report(domain).get("data", {}).get("attributes", {})
        return data.get("last_analysis_results", {})

    def domain_reputation(self, domain: str) -> int:
        return self.domain_report(domain)["data"]["attributes"].get("reputation", 0)

    def domain_categories(self, domain: str) -> Dict[str, List[str]]:
        return self.domain_report(domain)["data"]["attributes"].get("categories", {})

    def domain_whois_date(self, domain: str) -> Optional[str]:
        return self.domain_report(domain)["data"]["attributes"].get("whois_date")

    def domain_popularity_ranks(self, domain: str) -> Dict[str, Any]:
        return self.domain_report(domain)["data"]["attributes"].get("popularity_ranks", {})

    def domain_subdomains(self, domain: str, max_results: int = 100) -> List[str]:
        subdomains = []
        params = {"limit": 40}
        path = f"/domains/{domain}/subdomains"
        while len(subdomains) < max_results:
            resp = self._get(path, params)
            data = resp.get("data", [])
            if not data:
                break
            subdomains.extend([item["id"] for item in data])
            cursor = resp.get("meta", {}).get("cursor")
            if not cursor:
                break
            params["cursor"] = cursor
        return subdomains[:max_results]


class OSINTClient:
    """Combine VT and WHOIS lookups for enriched domain intelligence"""
    def __init__(self, vt_client: VirusTotalClient):
        self.vt = vt_client

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Utilise python-whois pour récupérer les données WHOIS complètes"""
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date,
                "name_servers": w.name_servers,
                "emails": w.emails,
                "status": w.status
            }
        except Exception as e:
            logging.error("Erreur WHOIS pour %s : %s", domain, e)
            return {}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Retourne un dict structuré mêlant VT et WHOIS"""
        vt_data = self.vt.domain_report(domain).get("data", {}).get("attributes", {})
        whois_info = self.get_whois_info(domain)

        return {
            "stats": vt_data.get("last_analysis_stats", {}),
            "results": vt_data.get("last_analysis_results", {}),
            "reputation": vt_data.get("reputation"),
            "categories": vt_data.get("categories"),
            "virustotal_whois_date": vt_data.get("whois_date"),
            "popularity_ranks": vt_data.get("popularity_ranks"),
            "subdomains": self.vt.domain_subdomains(domain),
            # WHOIS enrichi
            "whois_registrar": whois_info.get("registrar", "N/A"),
            "whois_creation_date": whois_info.get("creation_date", "N/A"),
            "whois_expiration_date": whois_info.get("expiration_date", "N/A"),
            "whois_name_servers": whois_info.get("name_servers", []),
            "whois_emails": whois_info.get("emails", []),
            "whois_status": whois_info.get("status", [])
        }
