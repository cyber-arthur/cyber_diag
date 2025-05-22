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

# ================== Config ==================
FONT_FAMILY     = "Helvetica"
CORPORATE_COLOR = (0, 51, 102)
CHART_SIZE      = (6, 3)
DATE_FORMAT     = "%d %B %Y %H:%M %Z"
TIMEZONE        = "Europe/Paris"
SOCIAL_REGEX    = re.compile(
    r'https?://(?:www\.)?(linkedin\.com/(?:company|in)|facebook\.com|'
    r'instagram\.com|twitter\.com)/[^/?#]+$'
)

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
        'subject'   : subject.get('commonName')      or subject.get('CN') or 'N/A',
        'not_before': cert.get('notBefore', 'N/A'),
        'not_after' : cert.get('notAfter',  'N/A')
    }

def fetch_http_headers(domain: str) -> dict:
    try:
        resp = requests.head(f"https://{domain}", timeout=5)
        return dict(resp.headers)
    except:
        return {}

def clean_osint_text(text: str) -> str:
    skip = ['missing api key','coded by','searching','exception','captcha','error','theharvester']
    lines = []
    for l in text.splitlines():
        t = l.strip()
        if not t or any(s in t.lower() for s in skip) or re.match(r"\*+", t):
            continue
        lines.append(t)
    return "\n".join(lines)

def fetch_social_links(domain: str) -> list[str]:
    """Fallback scrape homepage for social links if scraper missed them."""
    try:
        resp = requests.get(f"https://{domain}", timeout=5)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        found = set()
        for a in soup.find_all('a', href=True):
            u = a['href'].strip().rstrip('/')
            if SOCIAL_REGEX.match(u):
                found.add(u)
        return sorted(found)
    except:
        return []

# ================== PDF ==================
class PDF(FPDF):
    def __init__(self):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.set_auto_page_break(True, 15)
        self.set_title("Rapport de Diagnostic Cybersécurité")
        self.set_author("Cyber SES")

    def sanitize(self, s: str) -> str:
        return s.encode('latin-1', 'replace').decode('latin-1')

    def header(self):
        if self.page_no() > 2:
            self.set_font(FONT_FAMILY, 'B', 12)
            self.set_text_color(*CORPORATE_COLOR)
            self.cell(0, 10, self.sanitize("Cyber SES – Sécurisation TPE/PME"),
                      align='R')
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
            self.cell(0, 10, self.sanitize(f"Page {self.page_no()}"),
                      align='C')

    def cover_page(self, title: str, subtitle: str):
        self.add_page()
        self.set_fill_color(*CORPORATE_COLOR)
        self.rect(0,0,self.w,self.h,'F')
        self.set_text_color(255)
        self.set_font(FONT_FAMILY, 'B', 28)
        self.ln(100)
        self.cell(0,10, self.sanitize(title), ln=1, align='C')
        self.set_font(FONT_FAMILY, '', 16)
        self.cell(0,8,  self.sanitize(subtitle), ln=1, align='C')
        now = datetime.now(ZoneInfo(TIMEZONE))
        date_str = now.strftime(DATE_FORMAT)
        self.ln(10)
        self.set_font(FONT_FAMILY, 'I', 12)
        self.cell(0,10, self.sanitize(f"Date de génération : {date_str}"),
                  ln=1, align='C')

    def toc_page(self, secs: list[str]):
        self.add_page()
        self.set_font(FONT_FAMILY, 'B', 18)
        self.set_text_color(*CORPORATE_COLOR)
        self.cell(0,10,self.sanitize("Table des matières"),ln=1,align='C')
        self.ln(4)
        self.set_font(FONT_FAMILY, '',12)
        self.set_text_color(0)
        for s in secs:
            self.cell(0,8,self.sanitize(f"- {s}"),ln=1)
        self.ln(4)

    def section_title(self, t: str):
        self.set_font(FONT_FAMILY, 'B',14)
        self.set_text_color(*CORPORATE_COLOR)
        self.ln(4)
        self.cell(0,8,self.sanitize(t),ln=1)
        self.set_text_color(0)

    def subsection_title(self, t: str):
        self.set_font(FONT_FAMILY, '',12)
        self.set_text_color(80)
        self.ln(2)
        self.cell(0,6,self.sanitize(t),ln=1)
        self.set_text_color(0)

    def section_text(self, txt: str):
        self.set_font(FONT_FAMILY, '',10)
        self.multi_cell(0,5,self.sanitize(txt))
        self.ln(1)

    def add_image(self, path: str, w:int=100):
        if os.path.exists(path):
            self.image(path, w=w)
            self.ln(5)

# ================== Chart ==================
def generate_ports_chart(ips: dict, outdir: str) -> str|None:
    cnt = Counter()
    for d in ips.values():
        for ln in d.get('nmap','').splitlines():
            m = re.match(r"(\d+)/tcp", ln)
            if m: cnt[int(m.group(1))]+=1
    if not cnt: return None
    ports, occ = zip(*sorted(cnt.items()))
    plt.figure(figsize=CHART_SIZE)
    bars = plt.barh([str(p) for p in ports], occ, color='#003366')
    plt.xlabel("Occurrences")
    plt.ylabel("Port TCP")
    plt.title("Ports détectés (via Nmap)", color='#003366')
    plt.tight_layout()
    for b in bars:
        w = b.get_width()
        plt.text(w+0.2, b.get_y()+b.get_height()/2, str(int(w)),
                 va='center', fontsize=8)
    p = os.path.join(outdir,"nmap_ports.png")
    plt.savefig(p)
    plt.close()
    return p

# ================== Exportateur ==================
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

    ent    = resultats["entreprise"]
    vt     = resultats["resultats"]["virustotal"]
    emails = resultats["resultats"]["emails"]
    dns    = resultats["resultats"]["dns"]
    ips    = resultats["resultats"]["ips"]
    osint  = resultats["resultats"]["osint"]
    scrap  = resultats["resultats"]["scraping"]

    # Stats VT
    stats      = vt.get("stats",{})
    mal        = stats.get("malicious",0)
    susp       = stats.get("suspicious",0)
    harmless   = stats.get("harmless",0)
    reputation = vt.get("reputation","N/A")

    # Numéros valides
    raw_ph = scrap.get("phones",[])
    phones = [p for p in raw_ph if len(re.sub(r"\D","",p))>=8]

    # Liens sociaux
    socials = sorted(set(scrap.get("socials",[])) |
                    set(fetch_social_links(ent)))

    pdf = PDF()
    pdf.cover_page("Rapport de Diagnostic Cybersécurité",
                   f"{ent} (SIREN {siren})")
    pdf.toc_page(sections)
    pdf.add_page()

    # 1. Résumé
    pdf.section_title("Résumé")
    pdf.section_text(f"Domaine : {ent}")
    pdf.section_text(f"SIREN   : {siren}")
    risk = "Élevé" if mal>0 else "Modéré" if susp>0 else "Faible"
    pdf.section_text(f"Risque global : {risk}")
    pdf.section_text(
      f"Détails : {mal} détection(s) malveillante(s), "
      f"{susp} suspecte(s), {harmless} bénigne(s)  |  "
      f"Score réputation VT = {reputation}.")

    if mal>0:
        pdf.subsection_title("Moteurs Malveillants & verdicts")
        for eng,info in vt.get("results",{}).items():
            if info.get("category")=="malicious":
                det = info.get("result") or info.get("engine_name")
                pdf.section_text(f"- {eng}: {det}")

    # 2. WHOIS & Domaine
    pdf.section_title("WHOIS & Domaine")
    who = vt.get("whois",{})
    pdf.section_text(f"Registrar    : {who.get('registrar','N/A')}")
    pdf.section_text(f"Création     : {who.get('creation_date','N/A')}")
    pdf.section_text(f"Expiration   : {who.get('expiration_date','N/A')}")
    ns = who.get("name_servers",[])
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
        for k in ['Server','X-Frame-Options',
                  'Strict-Transport-Security','Content-Security-Policy']:
            v=hdr.get(k)
            if v: pdf.section_text(f"{k}: {v}")
    else:
        pdf.section_text("Aucun header HTTP récupéré.")

    # 5. Emails
    pdf.section_title("Emails détectés")
    if emails:
        for e in emails:
            pdf.section_text(f"- {e['email']} ({e.get('confidence','N/C')}%)")
    else:
        pdf.section_text("Aucun email détecté.")

    # 6. DNS
    pdf.section_title("DNS Records")
    for k,vals in dns.items():
        s = ', '.join(vals) if isinstance(vals,(list,tuple)) else vals
        pdf.section_text(f"{k}: {s}")

    # 7. Scans IP
    pdf.section_title("Scans IP")
    for ip,data in ips.items():
        pdf.subsection_title(ip)
        pdf.section_text(data.get("nmap",""))
        pdf.section_text("Shodan :")
        for kk,vv in data.get("shodan",{}).items():
            pdf.section_text(f"- {kk}: {vv}")

    # 8. Ports
    pdf.section_title("Ports détectés")
    chart = generate_ports_chart(ips,output_dir)
    if chart: pdf.add_image(chart, w=160)

    # 9. OSINT
    pdf.section_title("OSINT (theHarvester)")
    raw = osint.get("texte","")
    pdf.section_text(clean_osint_text(raw)[:2000] +
                     ("..." if len(raw)>2000 else ""))

    # 10. Scraping
    pdf.section_title("Scraping site web")
    for label,items in [
      ("Emails trouvés",       scrap.get("emails",[])),
      ("Téléphones trouvés",   phones),
      ("Adresses postales",    scrap.get("addresses",[])),
      ("Noms / Prénoms",       scrap.get("names",[])),
      ("Réseaux sociaux",      socials),
    ]:
        pdf.subsection_title(label)
        if items:
            for it in items:
                pdf.section_text(f"- {it}")
        else:
            pdf.section_text(f"Aucun {label.lower()}.")

    # 11. VT détails
    pdf.section_title("Détails VirusTotal")
    for k,v in stats.items():
        pdf.section_text(f"- {k}: {v}")

    findings = [(e,i['category']) for e,i in vt.get("results",{}).items()
                if i.get("category") in ("malicious","suspicious")]
    if findings:
        pdf.subsection_title("Moteurs détectant des menaces")
        for eng,cat in findings:
            pdf.section_text(f"- {eng}: {cat}")

    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(out)
    print(f"📁 Rapport PDF généré : {out}")
