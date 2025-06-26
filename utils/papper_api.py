# pappers_api.py
import requests

class PappersClient:
    BASE_URL = "https://api.pappers.fr/v2"

    def __init__(self, api_token: str):
        self.token = api_token

    def search_company(self, name: str):
        try:
            response = requests.get(f"{self.BASE_URL}/recherche", params={
                "api_token": self.token,
                "q": name
            })
            response.raise_for_status()
            return response.json().get("entreprises", [])
        except requests.RequestException as e:
            print(f"[!] Erreur lors de la recherche d'entreprise : {e}")
            return []

    def get_company_details(self, siren: str):
        try:
            response = requests.get(f"{self.BASE_URL}/entreprise", params={
                "api_token": self.token,
                "siren": siren
            })
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"[!] Erreur lors de la récupération des détails : {e}")
            return {}
