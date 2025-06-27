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

# === Configuration générale ===
FONT = "Helvetica"
CORPORATE_COLOR = (0, 51, 102)
CHART_SIZE = (6, 3)
DATE_FORMAT = "%d %B %Y %H:%M %Z"
TIMEZONE = "Europe/Paris"

SOCIAL_PATTERNS = {
    "linkedin": r'https?://(?:www\.)?linkedin\.com/(?:company|in)/[^/?#]+$',
    "facebook": r'https?://(?:www\.)?facebook\.com/[^/?#]+$',
    "instagram": r'https?://(?:www\.)?instagram\.com/[^/?#]+$',
    "twitter": r'https?://(?:www\.)?twitter\.com/[^/?#]+$'
}

HEADERS_INTEREST = [
    'Server', 'X-Frame-Options', 'Strict-Transport-Security', 'Content-Security-Policy'
]

# === Utilitaires réseau ===
def parse_cert_part(cert_section):
    result = {}
    for rdn in cert_section:
        for k, v in rdn:
            result[k] = v
    return result

def fetch_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = parse_cert_part(cert.get('issuer', []))
                subject = parse_cert_part(cert.get('subject', []))
                return {
                    'issuer': issuer.get('O') or issuer.get('organizationName', 'N/A'),
                    'subject': subject.get('CN') or subject.get('commonName', 'N/A'),
                    'not_before': cert.get('notBefore', 'N/A'),
                    'not_after': cert.get('notAfter', 'N/A')
                }
    except Exception as e:
        print(f"[⚠️ SSL] Erreur : {e}")
        return None

def fetch_headers(domain):
    try:
        return dict(requests.head(f"https://{domain}", timeout=5).headers)
    except Exception:
        return {}

def fetch_socials(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        return sorted({
            a['href'].strip().rstrip('/')
            for a in soup.find_all('a', href=True)
            if any(re.match(p, a['href']) for p in SOCIAL_PATTERNS.values())
        })
    except Exception:
        return []

# === PDF personnalisé ===
class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.set_title("Rapport CyberDiag")
        self.set_author("Cyber SES")

    def sanitize(self, t): return t.encode('latin-1', 'replace').decode('latin-1')

    def header(self):
        if self.page_no() > 2:
            self.set_font(FONT, 'B', 12)
            self.set_text_color(*CORPORATE_COLOR)
            self.cell(0, 6, self.sanitize("CyberDiag - Diagnostic Sécurité"), ln=1, align='R')
            self.set_draw_color(*CORPORATE_COLOR)
            self.line(10, self.get_y(), self.w - 10, self.get_y())
            self.ln(2)

    def footer(self):
        if self.page_no() > 2:
            self.set_y(-15)
            self.set_font(FONT, '', 8)
            self.set_text_color(128)
            self.cell(0, 10, f"Page {self.page_no()}", align='C')

    def add_section(self, title):
        self.ln(5)
        self.set_font(FONT, 'B', 14)
        self.set_text_color(*CORPORATE_COLOR)
        self.cell(0, 8, self.sanitize(title), ln=1)
        self.set_text_color(0)

    def add_text(self, text):
        self.set_font(FONT, '', 10)
        self.multi_cell(0, 5, self.sanitize(text))
        self.ln(1)

    def add_key_value(self, pairs):
        for label, value in pairs:
            self.set_font(FONT, '', 10)
            self.multi_cell(0, 5, f"{label} : {value}")
            self.ln(1)

    def add_image(self, path, width=100):
        if os.path.exists(path):
            self.image(path, w=width)
            self.ln(5)

# === Export PDF principal ===
def export_pdf(data, siren, output_dir):
    ent = data.get("entreprise", "N/A")
    results = data.get("resultats", {})
    vt, emails, dns, ips, scrap = (
        results.get(k, {}) for k in ("virustotal", "emails", "dns", "ips", "scraping")
    )

    pdf = PDF()
    pdf.add_page()
    pdf.set_font(FONT, 'B', 20)
    pdf.set_text_color(*CORPORATE_COLOR)
    pdf.cell(0, 15, f"Rapport CyberDiag - {ent}", ln=1, align='C')
    pdf.set_font(FONT, '', 12)
    pdf.set_text_color(0)
    pdf.cell(0, 10, f"SIREN : {siren}", ln=1, align='C')
    pdf.cell(0, 10, f"Généré le : {datetime.now(ZoneInfo(TIMEZONE)).strftime(DATE_FORMAT)}", ln=1, align='C')

    pdf.add_section("WHOIS & Domaine")
    who = vt.get("whois", {})
    pdf.add_key_value([
        ("Registrar", who.get('registrar', 'N/A')),
        ("Création", who.get('creation_date', 'N/A')),
        ("Expiration", who.get('expiration_date', 'N/A'))
    ])

    pdf.add_section("Certificat SSL")
    cert = fetch_certificate(ent)
    if cert:
        pdf.add_key_value([
            ("Émetteur", cert['issuer']),
            ("Sujet", cert['subject']),
            ("Valide du", cert['not_before']),
            ("au", cert['not_after'])
        ])
    else:
        pdf.add_text("❌ Impossible de récupérer les informations du certificat SSL.")

    pdf.add_section("Headers HTTP")
    headers = fetch_headers(ent)
    for k in HEADERS_INTEREST:
        if v := headers.get(k):
            pdf.add_text(f"{k} : {v}")

    pdf.add_section("Emails détectés")
    if emails:
        for e in emails:
            email = e.get("email", "Inconnu")
            conf = e.get("confidence", "N/C")
            sources = e.get("source", [])
            source_str = ', '.join(sources) if isinstance(sources, list) else str(sources)
            spf = e.get("SPF", "Non renseigné")
            dkim = e.get("DKIM", "Non renseigné")
            whois = e.get("whois", None)
            pdf.add_text(f"{email} (Confiance : {conf}%) | Source : {source_str}")
            pdf.add_text(" → SPF  :")
            pdf.add_text(spf)
            pdf.add_text(" → DKIM :")
            pdf.add_text(dkim)
            if whois:
                pdf.add_text(f" → WHOIS : {whois}")
    else:
        pdf.add_text("Aucun email détecté.")

    pdf.add_section("DNS Records")
    for k, v in dns.items():
        val = ', '.join(v) if isinstance(v, list) else v
        pdf.add_text(f"{k} : {val}")

    pdf.add_section("Analyse des IPs")
    for ip, data in ips.items():
        pdf.add_text(f"🔹 {ip}")
        if data.get("nmap"):
            pdf.add_text("Résultat Nmap :")
            pdf.add_text(data["nmap"])
        if data.get("shodan"):
            pdf.add_text("Shodan :")
            for key, val in data["shodan"].items():
                pdf.add_text(f" - {key}: {val}")

    pdf.add_section("Ports détectés")
    chart_path = os.path.join(output_dir, "nmap_ports.png")
    if os.path.exists(chart_path):
        pdf.add_image(chart_path, width=160)
    else:
        pdf.add_text("Aucun port détecté.")

    pdf.add_section("Analyse VirusTotal")
    vt_stats = vt.get("stats", {})
    reputation = vt.get("reputation", "N/A")
    categories = vt.get("categories", {})

    if vt_stats:
        pdf.add_text("Cette section présente le bilan de réputation du domaine selon VirusTotal :")
        pdf.add_text("- 'malicious' : nombre de moteurs ayant signalé ce domaine comme malveillant")
        pdf.add_text("- 'suspicious' : potentiellement dangereux, à surveiller")
        pdf.add_text("- 'harmless' : jugé sain par les moteurs")
        pdf.add_text("- 'undetected' : pas analysé ou aucun retour des moteurs")
        pdf.ln(1)

        for k, v in vt_stats.items():
            pdf.add_text(f"{k.capitalize()} : {v}")

        pdf.ln(1)
        pdf.add_text(f"Réputation générale (score VT) : {reputation}")

        if categories:
            cats = ', '.join([f"{src}: {cat}" for src, cat in categories.items()])
            pdf.add_text(f"Catégories associées : {cats}")

        pdf.ln(1)
        pdf.add_text("🔎 Astuce : un domaine avec un seul moteur 'malicious' n'est pas toujours dangereux, mais plusieurs signaux doivent alerter. Recoupez toujours avec le contexte métier.")
    else:
        pdf.add_text("Aucune donnée disponible depuis VirusTotal.")

    pdf.add_section("Réseaux sociaux détectés")
    socials = fetch_socials(ent)
    if socials:
        for url in socials:
            pdf.add_text(f"- {url}")
    else:
        pdf.add_text("Aucun lien social détecté sur le site.")

    out_path = os.path.join(output_dir, f"rapport_{siren}.pdf")
    pdf.output(out_path)
    print(f"✅ Rapport généré : {out_path}")
