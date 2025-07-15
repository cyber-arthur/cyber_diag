# utils/scanner.py

import re
from functools import lru_cache
from utils.helpers import run_command

# ================= Nmap scan optimisé =================
def nmap_scan(ip: str) -> str:
    """
    Scan rapide en deux phases :
    1) top 100 ports (-F) sans résolution DNS (-n), sans ping (-Pn), timing T4
    2) si on trouve des ports ouverts, on relance un scan de version (-sV) sur ces ports
    """
    # phase 1 : fast scan, sortie grepable
    fast_cmd = (
        f"nmap -T4 -Pn -n -F "
        f"--max-retries 1 --host-timeout 20s "
        f"{ip} -oG -"
    )
    out_fast, err_fast = run_command(fast_cmd)
    output = out_fast or err_fast

    # extraire les ports ouverts
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
    # phase 2 : version scan sur les ports ouverts
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
