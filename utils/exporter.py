from fpdf import FPDF
import os

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, "Rapport de Diagnostic Cybersécurité", 0, 1, "C")
        self.ln(3)

    def section_title(self, title):
        self.set_font("Arial", "B", 12)
        self.set_text_color(50, 50, 150)
        self.cell(0, 10, title.encode('latin-1', 'replace').decode('latin-1'), 0, 1)
        self.set_text_color(0, 0, 0)

    def subsection_title(self, title):
        self.set_font("Arial", "B", 11)
        self.set_text_color(90, 90, 90)
        self.cell(0, 8, title.encode('latin-1', 'replace').decode('latin-1'), 0, 1)
        self.set_text_color(0, 0, 0)

    def section_text(self, text):
        self.set_font("Arial", "", 10)
        self.multi_cell(0, 5, text.encode('latin-1', 'replace').decode('latin-1'))
        self.ln(1)

def export_pdf(resultats, siren, output_dir):
    pdf = PDF()
    pdf.add_page()

    entreprise = resultats.get('entreprise', 'N/A')
    pdf.set_title(f"Rapport - {entreprise}")

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

        shodan = ip_data.get("shodan", {})
        if isinstance(shodan, dict):
            pdf.section_text("Shodan:")
            for sk, sv in shodan.items():
                pdf.section_text(f"- {sk}: {sv}")
        else:
            pdf.section_text(f"Erreur Shodan: {shodan}")

    pdf.section_title("Résultat OSINT (theHarvester)")
    osint = resultats["resultats"].get("osint", {}).get("texte", "")
    pdf.section_text(osint[:5000])

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

    output_path = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(output_path)
    print(f"📁 Rapport PDF généré : {output_path}")
