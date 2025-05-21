import os
import re
import ssl
import socket
import requests
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo
from fpdf import FPDF
import matplotlib.pyplot as plt

# ================== Configurations ==================
FONT_FAMILY = "Helvetica"
CORPORATE_COLOR = (0, 51, 102)
CHART_SIZE = (6, 3)
DATE_FORMAT = "%d %B %Y %H:%M %Z"
TIMEZONE = "Europe/Paris"

# ================== Helpers: SSL Certificate & HTTP Headers ==================
def fetch_certificate_info(domain: str) -> dict:
    """Récupère le certificat TLS du domaine via socket"""
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.settimeout(5)
        s.connect((domain, 443))
        cert = s.getpeercert()

    # Flatten issuer and subject RDNs
    issuer_fields = {}
    subject_fields = {}
    for rdn in cert.get('issuer', []):
        for attr, val in rdn:
            issuer_fields[attr] = val
    for rdn in cert.get('subject', []):
        for attr, val in rdn:
            subject_fields[attr] = val

    issuer = issuer_fields.get('organizationName') or issuer_fields.get('O') or 'N/A'
    subject = subject_fields.get('commonName') or subject_fields.get('CN') or 'N/A'
    not_before = cert.get('notBefore', 'N/A')
    not_after = cert.get('notAfter', 'N/A')
    return {
        'issuer': issuer,
        'subject': subject,
        'not_before': not_before,
        'not_after': not_after
    }


def fetch_http_headers(domain: str) -> dict:
    """Effectue une requête HEAD pour récupérer les headers HTTP"""
    try:
        resp = requests.head(f"https://{domain}", timeout=5)
        return dict(resp.headers)
    except Exception:
        return {}

# ================== PDF Class ==================
class PDF(FPDF):
    def __init__(self):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.set_auto_page_break(auto=True, margin=15)
        self.set_title("Rapport de Diagnostic Cybersécurité")
        self.set_author("Cyber SES")

    def header(self):
        if self.page_no() > 2:
            self.set_font(FONT_FAMILY, 'B', 12)
            self.set_text_color(*CORPORATE_COLOR)
            self.cell(0, 10, "Cyber SES - Sécurisation TPE/PME", ln=False, align='R')
            self.ln(8)
            self.set_draw_color(*CORPORATE_COLOR)
            self.set_line_width(0.5)
            y = self.get_y()
            self.line(10, y, 200, y)
            self.ln(4)

    def footer(self):
        if self.page_no() > 2:
            self.set_y(-15)
            self.set_font(FONT_FAMILY, '', 8)
            self.set_text_color(128)
            self.cell(0, 10, f"Page {self.page_no()}", align='C')

    def cover_page(self, title: str, subtitle: str):
        self.add_page()
        self.set_fill_color(*CORPORATE_COLOR)
        self.rect(0, 0, self.w, self.h, 'F')
        self.set_text_color(255)
        self.set_font(FONT_FAMILY, 'B', 28)
        self.ln(100)
        self.cell(0, 10, title, ln=1, align='C')
        self.set_font(FONT_FAMILY, '', 16)
        self.ln(5)
        self.cell(0, 10, subtitle, ln=1, align='C')
        now = datetime.now(ZoneInfo(TIMEZONE))
        date_str = now.strftime(DATE_FORMAT)
        self.ln(10)
        self.set_font(FONT_FAMILY, 'I', 12)
        self.cell(0, 10, f"Date de génération : {date_str}", ln=1, align='C')

    def toc_page(self, sections: list):
        self.add_page()
        self.set_text_color(*CORPORATE_COLOR)
        self.set_font(FONT_FAMILY, 'B', 18)
        self.cell(0, 10, "Table des matières", ln=1, align='C')
        self.ln(5)
        self.set_text_color(0)
        self.set_font(FONT_FAMILY, '', 12)
        for sec in sections:
            self.cell(0, 8, f"- {sec}", ln=1)
        self.ln(5)

    def section_title(self, title: str):
        self.set_font(FONT_FAMILY, 'B', 14)
        self.set_text_color(*CORPORATE_COLOR)
        self.ln(4)
        self.cell(0, 8, title, ln=1)
        self.set_text_color(0)

    def subsection_title(self, title: str):
        self.set_font(FONT_FAMILY, 'B', 12)
        self.set_text_color(80)
        self.ln(2)
        self.cell(0, 6, title, ln=1)
        self.set_text_color(0)

    def section_text(self, text: str):
        self.set_font(FONT_FAMILY, '', 10)
        self.multi_cell(0, 5, text)
        self.ln(1)

    def add_image(self, image_path: str, w: int = 100):
        if os.path.exists(image_path):
            self.image(image_path, w=w)
            self.ln(5)

# ================== Chart Generation ==================
def generate_ports_chart(ips_data: dict, output_dir: str) -> str | None:
    port_counts = Counter()
    for data in ips_data.values():
        for line in data.get('nmap', '').splitlines():
            m = re.match(r"(\d+)/tcp", line)
            if m:
                port_counts[int(m.group(1))] += 1
    if not port_counts:
        return None
    ports, counts = zip(*sorted(port_counts.items()))
    plt.figure(figsize=CHART_SIZE)
    plt.bar(ports, counts)
    plt.title("Ports détectés (via Nmap)")
    plt.xlabel("Port TCP")
    plt.ylabel("Occurrences")
    plt.tight_layout()
    path = os.path.join(output_dir, "nmap_ports.png")
    plt.savefig(path)
    plt.close()
    return path

# ================== OSINT Cleaning ==================
def clean_osint_text(text: str) -> str:
    lines = text.splitlines()
    filtered = []
    skip_terms = ['missing api key', 'coded by', 'searching', 'exception', 'captcha', 'error', 'theharvester']
    for line in lines:
        lower = line.lower().strip()
        if not lower or any(term in lower for term in skip_terms) or re.match(r"\*+", lower):
            continue
        filtered.append(line.strip())
    return "\n".join(filtered)

# ================== Main Export Function ==================
def export_pdf(resultats: dict, siren: str, output_dir: str) -> None:
    sections = [
        "Résumé",
        "WHOIS & Domaine",
        "Certificat SSL/TLS",
        "Headers HTTP",
        "Emails détectés",
        "DNS Records",
        "Scans IP",
        "Ports détectés",
        "OSINT (theHarvester)",
        "Détails VirusTotal"
    ]
    entreprise = resultats.get("entreprise", "N/A")
    vt = resultats.get("resultats", {}).get("virustotal", {})
    emails_ext = resultats.get("resultats", {}).get("emails", [])
    dns = resultats.get("resultats", {}).get("dns", {})
    ips = resultats.get("resultats", {}).get("ips", {})

    pdf = PDF()
    # Page de garde
    pdf.cover_page(
        title="Rapport de Diagnostic Cybersécurité",
        subtitle=f"{entreprise} (SIREN {siren})"
    )
    # Sommaire
    pdf.toc_page(sections)
    pdf.add_page()

    # 1. Résumé
    pdf.section_title("Résumé")
    pdf.section_text(f"Domaine : {entreprise}")
    pdf.section_text(f"SIREN : {siren}")
    stats = vt.get("stats", {})
    risk = "Élevé" if stats.get("malicious", 0) > 0 else ("Modéré" if stats.get("suspicious", 0) > 0 else "Faible")
    pdf.section_text(f"Risque global : {risk}")

    # 2. WHOIS & Domaine
    pdf.section_title("WHOIS & Domaine")
    whois_info = vt.get("whois", {})
    pdf.section_text(f"Registrar    : {whois_info.get('registrar', 'N/A')}")
    pdf.section_text(f"Création     : {whois_info.get('creation_date', 'N/A')}")
    pdf.section_text(f"Expiration   : {whois_info.get('expiration_date', 'N/A')}")
    ns_list = whois_info.get('name_servers', [])
    pdf.section_text(f"Serveurs DNS : {', '.join(ns_list) if ns_list else 'N/A'}")

    # 3. Certificat SSL/TLS
    ssl_info = fetch_certificate_info(entreprise)
    pdf.section_title("Certificat SSL/TLS")
    pdf.section_text(f"Émetteur : {ssl_info['issuer']}")
    pdf.section_text(f"Sujet     : {ssl_info['subject']}")
    pdf.section_text(f"Valide du : {ssl_info['not_before']}")
    pdf.section_text(f"au        : {ssl_info['not_after']}")

    # 4. Headers HTTP
    headers = fetch_http_headers(entreprise)
    pdf.section_title("Headers HTTP")
    if headers:
        for k, v in headers.items():
            if k.lower() in ['server', 'x-frame-options', 'strict-transport-security', 'content-security-policy']:
                pdf.section_text(f"{k}: {v}")
    else:
        pdf.section_text("Aucun header HTTP récupéré.")

    # 5. Emails détectés
    pdf.section_title("Emails détectés")
    if emails_ext:
        for e in emails_ext:
            pdf.section_text(f"- {e.get('email')} ({e.get('confidence', 'N/C')}%)")
    else:
        pdf.section_text("Aucun email détecté.")

    # 6. DNS Records
    pdf.section_title("DNS Records")
    for k, vals in dns.items():
        vals_str = ', '.join(vals) if isinstance(vals, (list,tuple)) else vals
        pdf.section_text(f"{k}: {vals_str}")

    # 7. Scans IP
    pdf.section_title("Scans IP")
    for ip, data in ips.items():
        pdf.subsection_title(ip)
        pdf.section_text(data.get('nmap', ''))
        pdf.section_text('Shodan:')
        for k, v in data.get('shodan', {}).items():
            pdf.section_text(f"- {k}: {v}")

    # 8. Ports détectés
    pdf.section_title("Ports détectés")
    chart_path = generate_ports_chart(ips, output_dir)
    if chart_path:
        pdf.add_image(chart_path, w=160)

    # 9. OSINT (theHarvester)
    pdf.section_title("OSINT (theHarvester)")
    raw_text = resultats.get('resultats', {}).get('osint', {}).get('texte', '')
    cleaned = clean_osint_text(raw_text)
    snippet = cleaned[:2000] + ('...' if len(cleaned)>2000 else '')
    pdf.section_text(snippet)

    # 10. Détails VirusTotal
    pdf.section_title("Détails VirusTotal")
    for k, v in stats.items():
        pdf.section_text(f"- {k}: {v}")
    findings = [(eng, info.get('category')) for eng, info in vt.get('results', {}).items() if info.get('category') in ['malicious','suspicious']]
    if findings:
        pdf.section_text("Moteurs détectant des menaces:")
        for eng, cat in findings:
            pdf.section_text(f"- {eng}: {cat}")

    # Enregistrement
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(output_path)
    print(f"📁 Rapport PDF généré : {output_path}")
