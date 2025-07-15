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

# ================= Nmap scan =================
def nmap_scan(ip: str) -> str:
    """
    Scan rapide en deux phases :
    1) top 100 ports (-F) sans résolution DNS (-n), sans ping (-Pn), timing T4
    2) si on trouve des ports ouverts, on relance un scan de version (-sV) sur ces ports
    """
    # Phase 1 : fast scan en mode grepable
    fast_cmd = (
        f"nmap -T4 -Pn -n -F "
        f"--max-retries 1 --host-timeout 20s "
        f"{ip} -oG -"
    )
    out_fast, err_fast = run_command(fast_cmd)
    output = out_fast or err_fast

    # Extraire les ports ouverts
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

    # Phase 2 : scan de version sur ports ouverts
    if open_ports:
        ports_str = ",".join(open_ports)
        ver_cmd = (
            f"nmap -T4 -Pn -n -sV "
            f"--max-retries 1 --host-timeout 20s "
            f"-p {ports_str} {ip}"
        )
        out_ver, err_ver = run_command(ver_cmd)
        output += "\n\n" + (out_ver or err_ver)

    return output
