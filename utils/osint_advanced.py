import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "harmless": analysis.get("harmless"),
                "malicious": analysis.get("malicious"),
                "suspicious": analysis.get("suspicious"),
                "undetected": analysis.get("undetected")
            }
        else:
            return {"error": f"VirusTotal HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}
