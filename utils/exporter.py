from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, "Rapport de Diagnostic Cybersécurité", 0, 1, "C")
        self.ln(5)

    def section_title(self, title):
        self.set_font("Arial", "B", 11)
        self.set_text_color(30, 30, 30)
        self.cell(0, 10, title, 0, 1)
        self.set_text_color(0, 0, 0)

    def section_text(self, text):
        self.set_font("Arial", "", 10)
        self.multi_cell(0, 5, text)
        self.ln()

def export_pdf(resultats, siren):
    pdf = PDF()
    pdf.add_page()

    pdf.set_title(f"Rapport - {resultats['entreprise']}")

    pdf.section_title(f"📄 Rapport de Diagnostic - {resultats['entreprise']} ({siren})")
    pdf.ln(3)

    pdf.section_title("🧠 DNS Lookup")
    for k, v in resultats["resultats"]["dns"].items():
        line = f"{k}: {', '.join(v) if v else 'Aucune donnée'}"
        pdf.section_text(line)

    pdf.section_title("🖥️ Scans IP")
    for ip, data in resultats["resultats"]["ips"].items():
        pdf.section_text(f"🔹 IP: {ip}")
        pdf.section_text("  🔸 Nmap:\n" + data["nmap"])
        pdf.section_text("  🔸 Shodan:")
        for key, val in data["shodan"].items():
            pdf.section_text(f"    - {key}: {val}")

    pdf.section_title("🔎 OSINT (theHarvester)")
    osint_text = resultats["resultats"]["osint"].get("texte", "")[:5000]
    pdf.section_text(osint_text)

    pdf.section_title("📬 Emails collectés (Hunter.io)")
    emails = resultats["resultats"].get("emails", [])
    if emails:
        for email in emails:
            line = f"  - {email.get('email')} ({email.get('position') or 'poste inconnu'})"
            if email.get("phone_number"):
                line += f" 📞 {email.get('phone_number')}"
            pdf.section_text(line)
    else:
        pdf.section_text("  Aucun email trouvé.")

    output_path = f"diag_{siren}.pdf"
    pdf.output(output_path)
    print(f"📁 Rapport PDF généré : {output_path}")
