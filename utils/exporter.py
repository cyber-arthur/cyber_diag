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
from bs4 import BeautifulSoup

# ================== Configurations ==================
FONT_FAMILY     = "Helvetica"
CORPORATE_COLOR = (0, 51, 102)
CHART_SIZE      = (6, 3)
DATE_FORMAT     = "%d %B %Y %H:%M %Z"
TIMEZONE        = "Europe/Paris"

# ================== Helpers ==================
def fetch_certificate_info(domain: str) -> dict:
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.settimeout(5)
        s.connect((domain, 443))
        cert = s.getpeercert()
    issuer, subject = {}, {}
    for rdn in cert.get('issuer', []):
        for k, v in rdn:
            issuer[k] = v
    for rdn in cert.get('subject', []):
        for k, v in rdn:
            subject[k] = v
    return {
        'issuer'    : issuer.get('organizationName') or issuer.get('O') or 'N/A',
        'subject'   : subject.get('commonName') or subject.get('CN') or 'N/A',
        'not_before': cert.get('notBefore', 'N/A'),
        'not_after' : cert.get('notAfter', 'N/A')
    }

def fetch_http_headers(domain: str) -> dict:
    try:
        resp = requests.head(f"https://{domain}", timeout=5)
        return dict(resp.headers)
    except:
        return {}

def clean_osint_text(text: str) -> str:
    filtered = []
    skip = ['missing api key','coded by','searching','exception','captcha','error','theharvester']
    for line in text.splitlines():
        l = line.strip()
        if not l or any(s in l.lower() for s in skip):
            continue
        if re.match(r"\*+", l):
            continue
        filtered.append(l)
    return "\n".join(filtered)

def fetch_social_links(domain: str) -> list[str]:
    """Scrape the homepage for short social links."""
    try:
        resp = requests.get(f"https://{domain}", timeout=5)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        found = set()
        for a in soup.find_all('a', href=True):
            href = a['href'].strip().rstrip('/')
            if re.match(r'https?://(?:www\.)?linkedin\.com/(?:company|in)/[^/?#]+$', href):
                found.add(href)
            elif re.match(r'https?://(?:www\.)?facebook\.com/[^/?#]+$', href) and 'sharer' not in href:
                found.add(href)
            elif re.match(r'https?://(?:www\.)?instagram\.com/[^/?#]+$', href):
                found.add(href)
            elif re.match(r'https?://(?:www\.)?twitter\.com/[^/?#]+$', href) and 'intent' not in href:
                found.add(href)
        return sorted(found)
    except:
        return []

# ================== PDF Class ==================
class PDF(FPDF):
    def __init__(self):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.set_auto_page_break(auto=True, margin=15)
        self.set_title("Rapport de Diagnostic Cybersécurité")
        self.set_author("Cyber SES")

    def sanitize(self, text: str) -> str:
        return text.encode('latin-1', 'replace').decode('latin-1')

    def header(self):
        if self.page_no() > 2:
            self.set_font(FONT_FAMILY, 'B', 12)
            self.set_text_color(*CORPORATE_COLOR)
            self.cell(0, 10, self.sanitize("Cyber SES – Sécurisation TPE/PME"), align='R')
            self.ln(6)
            y = self.get_y()
            self.set_draw_color(*CORPORATE_COLOR)
            self.set_line_width(0.5)
            self.line(10, y, 200, y)
            self.ln(4)

    def footer(self):
        if self.page_no() > 2:
            self.set_y(-15)
            self.set_font(FONT_FAMILY, '', 8)
            self.set_text_color(128)
            self.cell(0, 10, self.sanitize(f"Page {self.page_no()}"), align='C')

    def cover_page(self, title: str, subtitle: str):
        self.add_page()
        self.set_fill_color(*CORPORATE_COLOR)
        self.rect(0, 0, self.w, self.h, 'F')
        self.set_text_color(255)
        self.set_font(FONT_FAMILY, 'B', 28)
        self.ln(100)
        self.cell(0, 10, self.sanitize(title), ln=1, align='C')
        self.set_font(FONT_FAMILY, '', 16)
        self.cell(0, 8, self.sanitize(subtitle), ln=1, align='C')
        now = datetime.now(ZoneInfo(TIMEZONE))
        date_str = now.strftime(DATE_FORMAT)
        self.ln(10)
        self.set_font(FONT_FAMILY, 'I', 12)
        self.cell(0, 10, self.sanitize(f"Date de génération : {date_str}"), ln=1, align='C')

    def toc_page(self, sections: list):
        self.add_page()
        self.set_font(FONT_FAMILY, 'B', 18)
        self.set_text_color(*CORPORATE_COLOR)
        self.cell(0, 10, self.sanitize("Table des matières"), ln=1, align='C')
        self.ln(4)
        self.set_font(FONT_FAMILY, '', 12)
        self.set_text_color(0)
        for sec in sections:
            self.cell(0, 8, self.sanitize(f"- {sec}"), ln=1)
        self.ln(4)

    def section_title(self, title: str):
        self.set_font(FONT_FAMILY, 'B', 14)
        self.set_text_color(*CORPORATE_COLOR)
        self.ln(4)
        self.cell(0, 8, self.sanitize(title), ln=1)
        self.set_text_color(0)

    def subsection_title(self, title: str):
        self.set_font(FONT_FAMILY, '', 12)
        self.set_text_color(80)
        self.ln(2)
        self.cell(0, 6, self.sanitize(title), ln=1)
        self.set_text_color(0)

    def section_text(self, text: str):
        self.set_font(FONT_FAMILY, '', 10)
        safe = self.sanitize(text)
        self.multi_cell(0, 5, safe)
        self.ln(1)

    def add_image(self, path: str, w: int = 100):
        if os.path.exists(path):
            self.image(path, w=w)
            self.ln(5)

# ================== Chart Generation ==================
def generate_ports_chart(ips_data: dict, output_dir: str) -> str | None:
    counts = Counter()
    for data in ips_data.values():
        for line in data.get('nmap','').splitlines():
            m = re.match(r"(\d+)/tcp", line)
            if m:
                counts[int(m.group(1))] += 1
    if not counts:
        return None
    ports, occ = zip(*sorted(counts.items()))
    plt.figure(figsize=CHART_SIZE)
    bars = plt.barh([str(p) for p in ports], occ, color='#003366')
    plt.xlabel("Occurrences")
    plt.ylabel("Port TCP")
    plt.title("Ports détectés (via Nmap)", color='#003366')
    plt.tight_layout()
    for bar in bars:
        w = bar.get_width()
        plt.text(w + 0.2, bar.get_y() + bar.get_height()/2,
                 str(int(w)), va='center', fontsize=8)
    path = os.path.join(output_dir, "nmap_ports.png")
    plt.savefig(path)
    plt.close()
    return path

# ================== Export PDF ==================
def export_pdf(resultats: dict, siren: str, output_dir: str):
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
        "Scraping site web",
        "Détails VirusTotal"
    ]

    ent    = resultats.get("entreprise", "N/A")
    vt     = resultats["resultats"].get("virustotal", {})
    emails = resultats["resultats"].get("emails", [])
    dns    = resultats["resultats"].get("dns", {})
    ips    = resultats["resultats"].get("ips", {})
    osint  = resultats["resultats"].get("osint", {})
    scrap  = resultats["resultats"].get("scraping", {})

    # Préparer données pour résumé détaillé
    stats      = vt.get("stats", {})
    mal        = stats.get("malicious", 0)
    susp       = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    reputation = vt.get("reputation", "N/A")

    # Filtrer numéros valides
    raw_phones = scrap.get("phones", [])
    phones = [p for p in raw_phones if len(re.sub(r"\D", "", p)) >= 8]

    # Récupérer liens sociaux
    socials = fetch_social_links(ent)

    pdf = PDF()
    pdf.cover_page("Rapport de Diagnostic Cybersécurité", f"{ent} (SIREN {siren})")
    pdf.toc_page(sections)
    pdf.add_page()

    # 1. Résumé
    pdf.section_title("Résumé")
    pdf.section_text(f"Domaine : {ent}")
    pdf.section_text(f"SIREN   : {siren}")
    risk = ("Élevé" if mal > 0 else "Modéré" if susp > 0 else "Faible")
    pdf.section_text(f"Risque global : {risk}")
    # Nouveau : explication du niveau de risque
    pdf.section_text(
        f"Détails du risque : {mal} détection(s) malveillante(s), "
        f"{susp} détection(s) suspecte(s), {harmless} analyse(s) bénigne(s) ; "
        f"score de réputation VT = {reputation}."
    )

    # 2. WHOIS & Domaine
    pdf.section_title("WHOIS & Domaine")
    who = vt.get("whois", {})
    pdf.section_text(f"Registrar    : {who.get('registrar','N/A')}")
    pdf.section_text(f"Création     : {who.get('creation_date','N/A')}")
    pdf.section_text(f"Expiration   : {who.get('expiration_date','N/A')}")
    ns = who.get("name_servers", [])
    pdf.section_text(f"Serveurs DNS : {', '.join(ns) if ns else 'N/A'}")

    # 3. Certificat SSL/TLS
    pdf.section_title("Certificat SSL/TLS")
    cert = fetch_certificate_info(ent)
    pdf.section_text(f"Émetteur    : {cert['issuer']}")
    pdf.section_text(f"Sujet       : {cert['subject']}")
    pdf.section_text(f"Valide du   : {cert['not_before']}")
    pdf.section_text(f"au          : {cert['not_after']}")

    # 4. Headers HTTP
    pdf.section_title("Headers HTTP")
    hdr = fetch_http_headers(ent)
    if hdr:
        for k in ['Server','X-Frame-Options','Strict-Transport-Security','Content-Security-Policy']:
            v = hdr.get(k)
            if v:
                pdf.section_text(f"{k}: {v}")
    else:
        pdf.section_text("Aucun header HTTP récupéré.")

    # 5. Emails détectés
    pdf.section_title("Emails détectés")
    if emails:
        for e in emails:
            pdf.section_text(f"- {e.get('email')} ({e.get('confidence','N/C')}%)")
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
        pdf.section_text(data.get("nmap",""))
        pdf.section_text("Shodan :")
        for kk, vv in data.get("shodan", {}).items():
            pdf.section_text(f"- {kk}: {vv}")

    # 8. Ports détectés
    pdf.section_title("Ports détectés")
    chart = generate_ports_chart(ips, output_dir)
    if chart:
        pdf.add_image(chart, w=160)

    # 9. OSINT (theHarvester)
    pdf.section_title("OSINT (theHarvester)")
    raw = osint.get("texte", "")
    pdf.section_text(clean_osint_text(raw)[:2000] + ("..." if len(raw) > 2000 else ""))

    # 10. Scraping site web
    pdf.section_title("Scraping site web")
    for label, items in [
        ("Emails trouvés",         scrap.get("emails", [])),
        ("Téléphones trouvés",     phones),
        ("Adresses postales",      scrap.get("addresses", [])),
        ("Noms / Prénoms trouvés", scrap.get("names", [])),
        ("Réseaux sociaux trouvés", socials),
    ]:
        pdf.subsection_title(label)
        if items:
            for entry in items:
                pdf.section_text(f"- {entry}")
        else:
            pdf.section_text(f"Aucun {label.lower()}.")

    # 11. Détails VirusTotal
    pdf.section_title("Détails VirusTotal")
    for k, v in stats.items():
        pdf.section_text(f"- {k}: {v}")
    findings = [
        (eng, info.get("category"))
        for eng, info in vt.get("results", {}).items()
        if info.get("category") in ("malicious","suspicious")
    ]
    if findings:
        pdf.section_text("Moteurs détectant des menaces :")
        for eng, cat in findings:
            pdf.section_text(f"- {eng}: {cat}")

    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(out)
    print(f"📁 Rapport PDF généré : {out}")