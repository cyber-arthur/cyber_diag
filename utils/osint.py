from utils.helpers import run_command

def osint_harvester(domain):
    cmd = f"python3 ~/cyber_diag/theHarvester/theHarvester.py -d {domain} -b all -l 200"
    out, err = run_command(cmd)
    if out:
        return {"texte": out.strip()}
    return {"error": err.strip()}
