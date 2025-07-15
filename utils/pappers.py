import requests
import os
from dotenv import load_dotenv

load_dotenv()
PAPPERS_API_KEY = os.getenv("PAPPERS_API_KEY")

if not PAPPERS_API_KEY:
    raise EnvironmentError("❌ Clé API Pappers manquante. Vérifie ton fichier .env.")

def fetch_pappers_data(siren: str) -> dict:
    """Appelle l'API Pappers et retourne les données brutes de l'entreprise."""
    url = "https://api.pappers.fr/v2/entreprise"
    params = {
        "api_token": PAPPERS_API_KEY,
        "siren": siren
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ Erreur API Pappers : {e}")
        return {}

def afficher_entreprise(data):
    siege = data.get("siege", {})

    print(f"\n🏢 {data.get('nom_entreprise', 'Inconnu')} — SIREN {data.get('siren')}")
    
    if data.get('forme_juridique'):
        print(f"📂 Forme juridique      : {data['forme_juridique']}")
    if data.get('categorie_entreprise'):
        print(f"🏷️  Catégorie entreprise : {data['categorie_entreprise']}")
    if data.get('capital'):
        print(f"💶 Capital social       : {data['capital']} €")
    if data.get('date_creation'):
        print(f"📆 Date immatriculation : {data['date_creation']}")
    if data.get('naf') or data.get('libelle_naf'):
        print(f"🏭 Activité (NAF)       : {data.get('naf', '')} — {data.get('libelle_naf', '')}")
    if data.get('statut_rcs'):
        print(f"🏛️  Statut RCS          : {data['statut_rcs']}")
    if data.get('tranche_effectif'):
        print(f"👥 Tranche d'effectif   : {data['tranche_effectif']}")
    if data.get('site_web'):
        print(f"🔗 Site Web             : {data['site_web']}")
    if data.get('telephone'):
        print(f"📞 Téléphone            : {data['telephone']}")

    adresse = []
    for champ in ["numero_voie", "type_voie", "libelle_voie", "code_postal", "ville"]:
        if siege.get(champ):
            adresse.append(str(siege[champ]))
    if adresse:
        print(f"📍 Adresse siège        : {' '.join(adresse)}")
    
    if siege.get("latitude") and siege.get("longitude"):
        print(f"🗺️  Coordonnées GPS      : {siege['latitude']}, {siege['longitude']}")

    if data.get('dernier_traitement'):
        print(f"🕓 Données mises à jour  : {data['dernier_traitement']}")

def afficher_dirigeants(data):
    dirigeants = data.get("dirigeants") or data.get("representants") or []
    if not dirigeants:
        return

    print("\n👥 Dirigeants :")
    for d in dirigeants:
        nom = d.get("nom", "")
        prenom = d.get("prenom", "")
        qualite = d.get("qualite", d.get("fonction", ""))
        date_debut = d.get("date_debut_mandat")
        ligne = f"  - {prenom} {nom} ({qualite})"
        if date_debut:
            ligne += f" — depuis {date_debut}"
        print(ligne)
