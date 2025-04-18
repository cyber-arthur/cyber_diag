from shodan import Shodan
from utils.helpers import run_command

def nmap_scan(ip):
    out, err = run_command(f"nmap -T4 -Pn -sV {ip}")
    return out if out else err.strip()

def shodan_scan(ip, api_key):
    try:
        api = Shodan(api_key)
        host = api.host(ip)
        return {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "hostnames": host.get("hostnames"),
            "ports": host.get("ports"),
            "tags": host.get("tags"),
        }
    except Exception as e:
        return {"error": str(e)}
