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
    """Récupère et aplatit le certificat TLS du domaine."""
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
        'issuer':     issuer.get('organizationName') or issuer.get('O') or 'N/A',
        'subject':    subject.get('commonName')      or subject.get('CN') or 'N/A',
        'not_before': cert.get('notBefore', 'N/A'),
        'not_after':  cert.get('notAfter',  'N/A')
    }

def fetch_http_headers(domain: str) -> dict:
    """HEAD request pour récupérer les headers HTTP principaux."""
    try:
        resp = requests.head(f"https://{domain}", timeout=5)
        return dict(resp.headers)
    except Exception:
        return {}

def clean_osint_text(text: str) -> str:
    skip = ['missing api key','coded by','searching','exception','captcha','error','theharvester']
    lines = []
    for line in text.splitlines():
        l = line.strip()
        if not l or any(k in l.lower() for k in skip) or re.match(r"\*+", l):
            continue
        lines.append(l)
    return "\n".join(lines)

def fetch_social_links(domain: str) -> list[str]:
    """Scrape la page d'accueil pour extraire les liens courts de réseaux sociaux."""
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
    except Exception:
        return []

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
        plt.text(w + 0.2, bar.get_y()+bar.get_height()/2, str(int(w)), va='center', fontsize=8)
    path = os.path.join(output_dir, "nmap_ports.png")
    plt.savefig(path)
    plt.close()
    return path

def generate_vt_pie_chart(stats: dict, output_dir: str) -> str | None:
    labels = []
    sizes  = []
    for k in ('malicious','suspicious','harmless'):
        v = stats.get(k, 0)
        if v > 0:
            labels.append(f"{k.capitalize()} ({v})")
            sizes.append(v)
    if not sizes:
        return None
    plt.figure(figsize=CHART_SIZE)
    plt.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=140)
    plt.title("Répartition VT", color='#003366')
    plt.tight_layout()
    path = os.path.join(output_dir, "vt_pie.png")
    plt.savefig(path)
    plt.close()
    return path

# ================== PDF Class ==================
class PDF(FPDF):
    def __init__(self):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.set_auto_page_break(auto=True, margin=15)
        self.set_title("Rapport de Diagnostic Cybersécurité")
        self.set_author("Cyber SES")

    def sanitize(self, t: str) -> str:
        return t.encode('latin-1', 'replace').decode('latin-1')

    def header(self):
        if self.page_no() > 2:
            self.set_font(FONT_FAMILY, 'B', 12)
            self.set_text_color(*CORPORATE_COLOR)
            self.cell(0, 6, self.sanitize("Cyber SES Sécurisation TPE/PME"), ln=1, align='R')
            y = self.get_y()
            self.set_draw_color(*CORPORATE_COLOR)
            self.line(10, y, self.w-10, y)
            self.ln(2)

    def footer(self):
        if self.page_no() > 2:
            self.set_y(-15)
            self.set_font(FONT_FAMILY, '', 8)
            self.set_text_color(128)
            self.cell(0, 10, self.sanitize(f"Page {self.page_no()}"), align='C')

    def cover_page(self, title: str, subtitle: str):
        self.add_page()
        self.set_fill_color(*CORPORATE_COLOR)
        self.rect(0,0,self.w,self.h,'F')
        self.set_text_color(255)
        self.set_font(FONT_FAMILY, 'B', 32)
        self.ln(80)
        self.cell(0, 12, self.sanitize(title), ln=1, align='C')
        self.set_font(FONT_FAMILY, '', 18)
        self.cell(0, 10, self.sanitize(subtitle), ln=1, align='C')
        now = datetime.now(ZoneInfo(TIMEZONE))
        date = now.strftime(DATE_FORMAT)
        self.ln(12)
        self.set_font(FONT_FAMILY, 'I', 12)
        self.cell(0, 8, self.sanitize(f"Date de génération : {date}"), ln=1, align='C')

    def toc_page(self, sections: list):
        self.add_page()
        self.set_font(FONT_FAMILY, 'B', 18)
        self.set_text_color(*CORPORATE_COLOR)
        self.cell(0, 10, self.sanitize("Table des matières"), ln=1, align='C')
        self.ln(4)
        self.set_font(FONT_FAMILY, '', 12)
        self.set_text_color(0)
        for i, sec in enumerate(sections, 1):
            self.cell(0, 8, self.sanitize(f"{i}. {sec}"), ln=1)
        self.ln(2)

    def section_title(self, title: str):
        self.ln(4)
        self.set_font(FONT_FAMILY, 'B', 14)
        self.set_text_color(*CORPORATE_COLOR)
        self.cell(0, 8, self.sanitize(title), ln=1)
        self.set_text_color(0)

    def subsection_title(self, title: str):
        self.set_font(FONT_FAMILY, 'B', 12)
        self.set_text_color(80)
        self.ln(2)
        self.cell(0, 6, self.sanitize(title), ln=1)
        self.set_text_color(0)

    def section_text(self, text: str):
        self.set_font(FONT_FAMILY, '', 10)
        self.multi_cell(0, 5, self.sanitize(text))
        self.ln(1)

    def add_image(self, img_path: str, w: int=100):
        if os.path.exists(img_path):
            self.image(img_path, w=w)
            self.ln(5)

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
        "Diagramme VirusTotal",
        "Scraping site web"
    ]

    ent    = resultats.get("entreprise", "N/A")
    vt     = resultats["resultats"].get("virustotal", {})
    emails = resultats["resultats"].get("emails", [])
    dns    = resultats["resultats"].get("dns", {})
    ips    = resultats["resultats"].get("ips", {})
    osint  = resultats["resultats"].get("osint", {})
    scrap  = resultats["resultats"].get("scraping", {})

    # Stats VT
    stats      = vt.get("stats", {})
    mal        = stats.get("malicious", 0)
    susp       = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    reputation = vt.get("reputation", "N/A")

    # Phones validés
    raw_phones = scrap.get("phones", [])
    phones = [p for p in raw_phones if len(re.sub(r"\D","",p)) >= 8]

    # Socials
    socials = fetch_social_links(ent)

    pdf = PDF()
    pdf.cover_page(
        "Rapport de Diagnostic Cybersécurité",
        f"{ent} (SIREN {siren})"
    )
    pdf.toc_page(sections)
    pdf.add_page()

    # 1. Résumé
    pdf.section_title("1. Résumé")
    pdf.section_text(f"Domaine       : {ent}")
    pdf.section_text(f"SIREN         : {siren}")
    risk = "Élevé" if mal>0 else "Modéré" if susp>0 else "Faible"
    pdf.section_text(f"Risque global : {risk}")
    pdf.section_text(
        f"Détails : {mal} détection(s) malveillante(s), "
        f"{susp} suspecte(s), {harmless} bénigne(s) ; "
        f"réputation VT = {reputation}."
    )

    # 2. WHOIS & Domaine
    pdf.section_title("2. WHOIS & Domaine")
    who = vt.get("whois", {})
    pdf.section_text(f"Registrar    : {who.get('registrar','N/A')}")
    pdf.section_text(f"Création     : {who.get('creation_date','N/A')}")
    pdf.section_text(f"Expiration   : {who.get('expiration_date','N/A')}")

    # 3. Certificat SSL/TLS
    pdf.section_title("3. Certificat SSL/TLS")
    cert = fetch_certificate_info(ent)
    pdf.section_text(f"Émetteur    : {cert['issuer']}")
    pdf.section_text(f"Sujet       : {cert['subject']}")
    pdf.section_text(f"Valide du   : {cert['not_before']}")
    pdf.section_text(f"au          : {cert['not_after']}")

    # 4. Headers HTTP
    pdf.section_title("4. Headers HTTP")
    hdr = fetch_http_headers(ent)
    if hdr:
        for k in ['Server','X-Frame-Options','Strict-Transport-Security','Content-Security-Policy']:
            v = hdr.get(k)
            if v:
                pdf.section_text(f"{k}: {v}")
    else:
        pdf.section_text("Aucun header HTTP récupéré.")

    # 5. Emails détectés
    pdf.section_title("5. Emails détectés")
    if emails:
        for idx, e in enumerate(emails, 1):
            pdf.section_text(f"{idx}. {e.get('email')} ({e.get('confidence','N/C')}%)")
    else:
        pdf.section_text("Aucun email détecté.")

    # 6. DNS Records
    pdf.section_title("6. DNS Records")
    for idx, (k, vals) in enumerate(dns.items(), 1):
        vals_str = ', '.join(vals) if isinstance(vals,(list,tuple)) else vals
        pdf.section_text(f"{idx}. {k}: {vals_str}")

    # 7. Scans IP
    pdf.section_title("7. Scans IP")
    for idx, (ip, data) in enumerate(ips.items(), 1):
        pdf.subsection_title(f"{idx}. {ip}")
        pdf.section_text(data.get("nmap","").strip() or "Pas de résultat Nmap.")
        pdf.section_text("Shodan :")
        for subidx, (kk, vv) in enumerate(data.get("shodan",{}).items(),1):
            pdf.section_text(f"   {subidx}. {kk}: {vv}")

    # 8. Ports détectés
    pdf.section_title("8. Ports détectés")
    chart = generate_ports_chart(ips, output_dir)
    if chart:
        pdf.add_image(chart, w=160)
    else:
        pdf.section_text("Aucun port détecté.")

    # 9. Diagramme VirusTotal
    pdf.section_title("9. Diagramme VirusTotal")
    pie = generate_vt_pie_chart(stats, output_dir)
    if pie:
        pdf.add_image(pie, w=120)
        pdf.section_text(
            "- Malicious : détections confirmées\n"
            "- Suspicious : analyses à vérifier\n"
            "- Harmless : résultats bénins"
        )
    else:
        pdf.section_text("Pas de données VT à afficher.")

    # 10. Scraping site web
    pdf.section_title("10. Scraping site web")
    categories = [
        ("Emails trouvés",         scrap.get("emails", [])),
        ("Téléphones trouvés",     phones),
        ("Adresses postales",      scrap.get("addresses", [])),
        ("Noms / Prénoms trouvés", scrap.get("names", [])),
        ("Réseaux sociaux trouvés", socials),
    ]
    for num, (label, items) in enumerate(categories, 1):
        pdf.subsection_title(f"{num}. {label}")
        if items:
            for j, entry in enumerate(items, 1):
                pdf.section_text(f"{j}. {entry}")
        else:
            pdf.section_text(f"Aucun {label.lower()}.")

    # Enregistrement
    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(out)
    print(f"📁 Rapport PDF généré : {out}")
