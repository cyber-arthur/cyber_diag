import re
import subprocess

def run_command(cmd: str) -> tuple[str, str]:
    """
    Exécute une commande shell et retourne (stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=False
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

# ================= Nmap scan top 5000 ports =================
def nmap_scan(ip: str) -> str:
    """
    Scan Nmap complet (sans timeout) sur les 5000 ports les plus courants.
    Deux étapes :
    1) top 5000 ports (avec -T4, -Pn, --top-ports)
    2) scan de version (-sV) sur ports ouverts
    """
    # Phase 1 : détection rapide sans limite de temps
    fast_cmd = f"nmap -T4 -Pn -n --top-ports 5000 {ip} -oG -"
    out_fast, err_fast = run_command(fast_cmd)
    output = out_fast or err_fast

    # Extraction des ports ouverts
    open_ports = []
    for line in output.splitlines():
        if line.startswith("Host"):
            m = re.search(r"Ports:\s*(.*)", line)
            if m:
                for part in m.group(1).split(","):
                    part = part.strip()
                    if "/open/" in part:
                        port = part.split("/")[0]
                        open_ports.append(port)

    # Phase 2 : scan de version si ports ouverts
    if open_ports:
        ports_str = ",".join(open_ports)
        ver_cmd = f"nmap -T4 -Pn -n -sV -p {ports_str} {ip}"
        out_ver, err_ver = run_command(ver_cmd)
        output += "\n\n" + (out_ver or err_ver)

    return output
