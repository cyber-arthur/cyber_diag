from fpdf import FPDF
import os
import re

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

    def add_toc(self, titles):
        self.add_page()
        self.set_font("Arial", "B", 14)
        self.cell(0, 10, "Table des matières", 0, 1, "C")
        self.set_font("Arial", "", 10)
        for title in titles:
            safe_title = title.encode('latin-1', 'replace').decode('latin-1')
            self.cell(0, 8, f"- {safe_title}", 0, 1)
        self.ln(5)

    def safe_output(self, name):
        try:
            self.output(name)
        except UnicodeEncodeError as e:
            print("[Erreur PDF] Caractère non compatible latin-1 détecté :", e)
            raise

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
