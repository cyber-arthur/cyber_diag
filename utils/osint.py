import subprocess
import os

def osint_harvester(domain: str) -> dict:
    print(f"🔍 Lancement de theHarvester pour {domain}...\n")
    script_path = os.path.join("theHarvester", "theHarvester.py")
    cmd = [
        "python3", script_path,
        "-d", domain,
        "-b", "bing",  # Tu peux changer "bing" par "all" ou autre
        "-l", "50"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return {"texte": result.stdout.strip()}
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr.strip()}
