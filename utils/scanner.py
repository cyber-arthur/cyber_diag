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

# ================= Nmap scan sur ports 1 à 10000 =================
def nmap_scan(ip: str) -> str:
    """
    Scan Nmap en deux phases :
    1) scan ports 1-10000 (-p 1-10000), sans DNS ni ping, format grepable
    2) scan de version (-sV) uniquement sur les ports ouverts détectés
    """
    # Phase 1 : détection large
    fast_cmd = (
        f"nmap -T4 -Pn -n -p 1-10000 "
        f"--max-retries 1 --host-timeout 90s "
        f"{ip} -oG -"
    )
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

    # Phase 2 : scan de version
    if open_ports:
        ports_str = ",".join(open_ports)
        ver_cmd = (
            f"nmap -T4 -Pn -n -sV "
            f"--max-retries 1 --host-timeout 120s "
            f"-p {ports_str} {ip}"
        )
        out_ver, err_ver = run_command(ver_cmd)
        output += "\n\n" + (out_ver or err_ver)

    return output
