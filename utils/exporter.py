from fpdf import FPDF
import os
import re
from collections import Counter
import matplotlib.pyplot as plt
from datetime import datetime

class PDF(FPDF):
    def header(self):
        # En-tête simple après page de garde et sommaire
        if self.page_no() > 2:
            self.set_font("Arial", "I", 8)
            self.set_text_color(100)
            self.cell(0, 10, f"CYBERSES - Page {self.page_no()}", 0, 0, "R")
            self.ln(5)
            self.set_draw_color(200)
            self.set_line_width(0.2)
            y = self.get_y()
            self.line(10, y, 200, y)
            self.ln(2)

    def footer(self):
        # Numérotation en bas de page
        if self.page_no() > 2:
            self.set_y(-15)
            self.set_font("Arial", "I", 8)
            self.set_text_color(128)
            self.cell(0, 10, f"Page {self.page_no()}", 0, 0, "C")

    def cover_page(self, title: str, subtitle: str):
        # Page de garde personnalisée
        self.add_page()
        self.set_fill_color(50, 50, 150)
        self.rect(0, 0, self.w, self.h, 'F')
        self.set_text_color(255)
        self.set_font("Arial", "B", 24)
        self.ln(60)
        self.cell(0, 10, title, 0, 1, "C")
        self.set_font("Arial", "", 16)
        self.ln(10)
        self.cell(0, 10, subtitle, 0, 1, "C")
        # Date
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        self.ln(10)
        self.set_font("Arial", "I", 12)
        self.cell(0, 10, f"Date de génération : {date_str}", 0, 1, "C")

    def toc_page(self, sections: list):
        # Page de sommaire
        self.add_page()
        self.set_text_color(30, 30, 30)
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "Table des matières", 0, 1, "C")
        self.ln(5)
        self.set_font("Arial", "", 12)
        for sec in sections:
            # On ne met pas numéros de page dynamiques pour l'instant
            self.cell(0, 8, f"- {sec}", 0, 1)
        self.ln(5)

    def section_title(self, title):
        self.set_font("Arial", "B", 14)
        self.set_text_color(0, 70, 140)
        self.ln(2)
        safe_title = title.encode('latin-1', 'replace').decode('latin-1')
        self.cell(0, 8, safe_title, 0, 1)
        self.set_text_color(0, 0, 0)

    def subsection_title(self, title):
        self.set_font("Arial", "B", 12)
        self.set_text_color(90, 90, 90)
        safe_title = title.encode('latin-1', 'replace').decode('latin-1')
        self.ln(1)
        self.cell(0, 6, safe_title, 0, 1)
        self.set_text_color(0, 0, 0)

    def section_text(self, text):
        self.set_font("Arial", "", 10)
        safe_text = text.encode('latin-1', 'replace').decode('latin-1')
        self.multi_cell(0, 5, safe_text)
        self.ln(1)

    def add_image(self, image_path, w=100):
        if os.path.exists(image_path):
            self.image(image_path, w=w)
            self.ln(5)


def generate_ports_chart(ips_data, output_dir):
    port_counts = Counter()
    for ip_data in ips_data.values():
        for line in ip_data.get("nmap", "").splitlines():
            m = re.match(r"(\d+)/tcp", line)
            if m:
                port_counts[m.group(1)] += 1
    if port_counts:
        ports, counts = zip(*sorted(port_counts.items(), key=lambda x: int(x[0])))
        plt.figure(figsize=(6, 3))
        plt.bar(ports, counts)
        plt.title("Ports détectés (via Nmap)")
        plt.xlabel("Port TCP")
        plt.ylabel("Occurrences")
        plt.tight_layout()
        path = os.path.join(output_dir, "nmap_ports.png")
        plt.savefig(path)
        plt.close()
        return path
    return None


def clean_osint_text(text):
    lines = text.splitlines()
    clean = []
    for line in lines:
        if any(skip in line.lower() for skip in ["missing api key","coded by","searching","exception","captcha","error"]):
            continue
        if re.match(r"\*+", line) or line.strip() == '' or 'theHarvester' in line:
            continue
        clean.append(line.strip())
    return "\n".join(clean)


def export_pdf(resultats, siren, output_dir):
    # Définition des sections pour le sommaire
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
    vt = resultats["resultats"].get("virustotal", {})
    whois = vt.get("whois", {})
    emails_site = resultats["resultats"].get("emails_crawl", [])
    emails_ext = resultats["resultats"].get("emails", [])
    dns = resultats["resultats"].get("dns", {})
    ips = resultats["resultats"].get("ips", {})
    ssl = vt.get("ssl", {})
    headers = vt.get("http_headers", {})

    pdf = PDF()
    # Page de garde
    pdf.cover_page(
        title="Rapport de Diagnostic Cybersécurité",
        subtitle=f"{entreprise} ({siren})"
    )
    # Sommaire
    pdf.toc_page(sections)
    # Contenu
    pdf.add_page()

    # 1. Résumé
    pdf.section_title("Résumé")
    pdf.section_text(f"Domaine : {entreprise}")
    pdf.section_text(f"SIREN   : {siren}")
    risk = "Faible"
    if vt.get("stats", {}).get("malicious",0)>0:
        risk = "Élevé"
    elif vt.get("stats", {}).get("suspicious",0)>0:
        risk = "Modéré"
    pdf.section_text(f"Risque VT: {risk}")

    # 2. WHOIS & Domaine
    pdf.section_title("WHOIS & Domaine")
    pdf.section_text(f"Registrar    : {whois.get('registrar','N/A')}")
    creation = whois.get('creation_date')
    exp = whois.get('expiration_date')
    pdf.section_text(f"Création     : {creation if creation else 'N/A'}")
    pdf.section_text(f"Expiration   : {exp if exp else 'N/A'}")
    pdf.section_text(f"Propriétaire : {whois.get('owner','N/A')}")
    ns = whois.get('name_servers', [])
    pdf.section_text(f"Serveurs DNS : {', '.join(ns) if ns else 'N/A'}")

    # 3. Certificat SSL/TLS
    pdf.section_title("Certificat SSL/TLS")
    pdf.section_text(f"Émetteur      : {ssl.get('issuer','N/A')}")
    pdf.section_text(f"Sujet         : {ssl.get('subject','N/A')}")
    pdf.section_text(f"Valide du     : {ssl.get('not_before','N/A')}")
    pdf.section_text(f"au            : {ssl.get('not_after','N/A')}")

    # 4. Headers HTTP
    pdf.section_title("Headers HTTP")
    for k,v in headers.items():
        if k.lower() in ['server','x-frame-options','strict-transport-security','content-security-policy']:
            pdf.section_text(f"{k}: {v}")

    # 5. Emails détectés
    pdf.section_title("Emails détectés")
    if emails_ext or emails_site:
        pdf.subsection_title("Externe (Hunter.io)")
        for e in emails_ext: pdf.section_text(f"- {e.get('email')} ({e.get('confidence', 'N/C')}%)")
        pdf.subsection_title("Site web")
        for e in emails_site: pdf.section_text(f"- {e}")
    else:
        pdf.section_text("Aucun email détecté.")

    # 6. DNS Records
    pdf.section_title("DNS Records")
    for k, vals in dns.items():
        pdf.section_text(f"{k}: {', '.join(vals) if isinstance(vals,(list,tuple)) else vals}")

    # 7. Scans IP
    pdf.section_title("Scans IP")
    for ip, data in ips.items():
        pdf.subsection_title(ip)
        pdf.section_text(data.get('nmap',''))
        pdf.section_text('')
        pdf.section_text('Shodan:')
        for k,v in data.get('shodan',{}).items(): pdf.section_text(f"- {k}: {v}")

    # 8. Ports détectés
    pdf.section_title("Ports détectés")
    chart = generate_ports_chart(ips, output_dir)
    if chart:
        pdf.add_image(chart, w=160)

    # 9. OSINT (theHarvester)
    pdf.section_title("OSINT (theHarvester)")
    raw = resultats['resultats'].get('osint',{}).get('texte','')
    cleaned = clean_osint_text(raw)
    pdf.section_text(cleaned[:2000] + ('...' if len(cleaned)>2000 else ''))

    # 10. Détails VirusTotal
    pdf.section_title("Détails VirusTotal")
    for k,v in vt.get('stats',{}).items(): pdf.section_text(f"- {k}: {v}")
    findings = [(eng,info.get('category')) for eng,info in vt.get('results',{}).items() if info.get('category') in ['malicious','suspicious']]
    if findings:
        pdf.section_text("Moteurs détectant des menaces:")
        for eng,cat in findings: pdf.section_text(f"- {eng}: {cat}")

    # Enregistrement du PDF
    out = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(out)
    print(f"📁 Rapport PDF généré : {out}")
