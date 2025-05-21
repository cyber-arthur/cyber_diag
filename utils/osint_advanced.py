import os
import time
import logging
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# Chargement de la clé d'API depuis .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("Il faut définir VT_API_KEY dans votre .env")


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
            time.sleep(self.RATE_LIMIT_SLEEP)
            return self._get(path, params)
        resp.raise_for_status()
        return resp.json()

    def domain_report(self, domain: str) -> Dict[str, Any]:
        """Rapport global sur le domaine."""
        return self._get(f"/domains/{domain}")

    def domain_analysis_stats(self, domain: str) -> Dict[str, int]:
        """Statistiques d’analyse (harmless, malicious, etc.)."""
        data = self.domain_report(domain).get("data", {}).get("attributes", {})
        return data.get("last_analysis_stats", {})

    def domain_analysis_results(self, domain: str) -> Dict[str, Any]:
        """Détails des résultats d’analyse par moteur."""
        data = self.domain_report(domain).get("data", {}).get("attributes", {})
        return data.get("last_analysis_results", {})

    def domain_reputation(self, domain: str) -> int:
        """Score de réputation (-100 à +100)."""
        return self.domain_report(domain)["data"]["attributes"].get("reputation", 0)

    def domain_categories(self, domain: str) -> Dict[str, List[str]]:
        """Catégories assignées par VT ou partenaires."""
        return self.domain_report(domain)["data"]["attributes"].get("categories", {})

    def domain_whois_date(self, domain: str) -> Optional[str]:
        """Date d’enregistrement WHOIS (si disponible)."""
        return self.domain_report(domain)["data"]["attributes"].get("whois_date")

    def domain_popularity_ranks(self, domain: str) -> Dict[str, Any]:
        """Rangs de popularité (Alexa, etc.)."""
        return self.domain_report(domain)["data"]["attributes"].get("popularity_ranks", {})

    def domain_subdomains(self, domain: str, max_results: int = 100) -> List[str]:
        """Récupère les sous-domaines, avec pagination."""
        subdomains = []
        params = {"limit": 40}
        path = f"/domains/{domain}/subdomains"
        while len(subdomains) < max_results:
            data = self._get(path, params).get("data", [])
            if not data:
                break
            subdomains.extend([item["id"] for item in data])
            # Pagination
            cursor = self._get(path, params).get("meta", {}).get("cursor")
            if not cursor:
                break
            params["cursor"] = cursor
        return subdomains[:max_results]

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Fonction tout-en-un renvoyant un dict structuré."""
        report = self.domain_report(domain).get("data", {}).get("attributes", {})
        return {
            "stats": report.get("last_analysis_stats", {}),
            "results": report.get("last_analysis_results", {}),
            "reputation": report.get("reputation"),
            "categories": report.get("categories"),
            "whois_date": report.get("whois_date"),
            "popularity_ranks": report.get("popularity_ranks"),
            "subdomains": self.domain_subdomains(domain),
        }
