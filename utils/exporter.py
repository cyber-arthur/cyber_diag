from fpdf import FPDF
import os
import re
from collections import Counter
import matplotlib.pyplot as plt

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.set_text_color(30, 30, 30)
        header = "CYBERSES - Rapport de Diagnostic Cybersécurité"
        self.cell(0, 10, header.encode('latin-1', 'replace').decode('latin-1'), 0, 1, "C")
        self.set_font("Arial", "", 10)
        self.cell(0, 10, "Simple and Efficient Security", 0, 1, "C")
        self.ln(4)
        self.set_draw_color(50, 50, 150)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def section_title(self, title):
        self.set_font("Arial", "B", 12)
        self.set_text_color(0, 70, 140)
        safe_title = title.encode('latin-1', 'replace').decode('latin-1')
        self.cell(0, 10, safe_title, 0, 1)
        self.set_text_color(0, 0, 0)

    def subsection_title(self, title):
        self.set_font("Arial", "B", 11)
        self.set_text_color(90, 90, 90)
        safe_title = title.encode('latin-1', 'replace').decode('latin-1')
        self.cell(0, 8, safe_title, 0, 1)
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

def clean_osint_text(text):
    lines = text.splitlines()
    clean_lines = []
    for line in lines:
        if any(skip in line.lower() for skip in [
            "missing api key", "coded by", "searching", "an exception", "attempt to decode", "captcha",
            "error", "report any incorrect", "submit", "defaultsite", "rapiddns"]):
            continue
        if re.match(r"\*+", line):
            continue
        if line.strip() == '' or 'theHarvester' in line or 'Target:' in line:
            continue
        clean_lines.append(line.strip())
    return "\n".join(clean_lines)

def generate_ports_chart(ips_data, output_dir):
    port_counts = Counter()
    for ip_data in ips_data.values():
        nmap_output = ip_data.get("nmap", "")
        for line in nmap_output.splitlines():
            match = re.match(r"(\d+)/tcp", line)
            if match:
                port = match.group(1)
                port_counts[port] += 1

    if port_counts:
        ports = list(port_counts.keys())
        counts = list(port_counts.values())
        plt.figure(figsize=(8, 4))
        plt.bar(ports, counts, color='steelblue')
        plt.title("Ports détectés (via Nmap)")
        plt.xlabel("Port TCP")
        plt.ylabel("Occurrences")
        plt.tight_layout()
        chart_path = os.path.join(output_dir, "nmap_ports.png")
        plt.savefig(chart_path)
        plt.close()
        return chart_path
    return None

def export_pdf(resultats, siren, output_dir):
    from utils.osint_advanced import check_greynoise, check_virustotal

    pdf = PDF()
    pdf.set_title(f"Rapport - {resultats.get('entreprise', 'N/A')}")
    pdf.add_page()

    entreprise = resultats.get('entreprise', 'N/A')
    pdf.section_title(f"Informations générales - {entreprise} ({siren})")
    siren_data = resultats["resultats"].get("siren_data", {})
    for k, v in siren_data.items():
        pdf.section_text(f"{k}: {v}")

    pdf.section_title("Résultat DNS")
    dns_result = resultats["resultats"].get("dns", {})
    for k, v in dns_result.items():
        val = ', '.join(v) if v else 'Aucune donnée'
        pdf.section_text(f"{k}: {val}")

    pdf.section_title("Résultat des Scans IP")
    ips = resultats["resultats"].get("ips", {})
    for ip, ip_data in ips.items():
        pdf.subsection_title(f"Adresse IP : {ip}")
        pdf.section_text("Nmap:")
        pdf.section_text(ip_data.get("nmap", "Aucune donnée"))

        pdf.section_text("Shodan:")
        shodan = ip_data.get("shodan", {})
        if isinstance(shodan, dict):
            for sk, sv in shodan.items():
                if sv:
                    pdf.section_text(f"- {sk}: {sv}")
        else:
            pdf.section_text(f"Erreur Shodan: {shodan}")

        # ➕ GreyNoise enrichment
        greynoise_data = check_greynoise(ip)
        pdf.section_text("GreyNoise:")
        for gk, gv in greynoise_data.items():
            pdf.section_text(f"- {gk}: {gv}")

    # ➕ Ajout du graphique Nmap
    chart_path = generate_ports_chart(ips, output_dir)
    if chart_path:
        pdf.section_title("Visualisation des ports détectés")
        pdf.add_image(chart_path, w=160)

    pdf.section_title("Résultat OSINT (theHarvester)")
    osint_raw = resultats["resultats"].get("osint", {}).get("texte", "")
    cleaned_osint = clean_osint_text(osint_raw)
    pdf.section_text(cleaned_osint[:5000])

    pdf.section_title("Analyse VirusTotal (Domaine)")
    vt_data = check_virustotal(entreprise)
    for k, v in vt_data.items():
        pdf.section_text(f"- {k}: {v}")

    pdf.section_title("Emails collectés (Hunter.io)")
    emails = resultats["resultats"].get("emails", [])
    if emails:
        for email in emails:
            if isinstance(email, dict):
                email_text = f"- {email.get('email')} ({email.get('position') or 'poste inconnu'})"
                if email.get("first_name") or email.get("last_name"):
                    email_text += f" - {email.get('first_name', '')} {email.get('last_name', '')}"
                if email.get("phone_number"):
                    email_text += f" - 📞 {email.get('phone_number')}"
                if email.get("confidence"):
                    email_text += f" - 🔒 Confiance: {email.get('confidence')}%"
                pdf.section_text(email_text)
                if sources := email.get("sources"):
                    pdf.section_text("  Sources:")
                    for src in sources:
                        pdf.section_text(f"    - {src.get('uri', '')}")
            else:
                pdf.section_text(f"- {email}")
    else:
        pdf.section_text("Aucun email trouvé.")

    pdf.section_title("Synthèse et Recommandations")
    pdf.section_text("Ce rapport fournit un aperçu de la posture de sécurité externe de l'entreprise. Il est recommandé :")
    pdf.section_text("- De corriger toute configuration exposée détectée via Shodan, GreyNoise ou Nmap.")
    pdf.section_text("- D’analyser les emails identifiés et les points de fuite d’informations.")
    pdf.section_text("- D’utiliser ces informations pour alimenter un plan d’actions cybersécurité.")

    output_path = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(output_path)
    print(f"📁 Rapport PDF généré : {output_path}")
