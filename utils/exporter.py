from fpdf import FPDF
import os
import re
from collections import Counter
import matplotlib.pyplot as plt

def safe_extract(data: dict, fields: list):
    if "error" in data:
        return []
    return [f"{field}: {data.get(field, 'N/A')}" for field in fields]

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
        clean = text.replace('’', "'")
        safe_text = clean.encode('latin-1', 'replace').decode('latin-1')
        self.multi_cell(0, 5, safe_text)
        self.ln(1)

    def ip_summary(self, ip, services, greynoise):
        summary = f"[IP] {ip} — "
        if greynoise.get("classification") == "malicious":
            summary += "⚠️ Activité malveillante détectée"
        elif greynoise.get("classification") == "benign":
            summary += "✅ Activité bénigne"
        else:
            summary += "❓ Non classée"

        if any(port in services for port in ["21", "23", "445"]):
            summary += " | ⚠️ Ports sensibles exposés"
        return summary

    def draw_score_block(self, items):
        self.set_font("Arial", "B", 12)
        self.set_fill_color(245, 245, 245)
        for label, status in items:
            symbol = "✅" if status else "⛔"
            line = f"{symbol} {label}"
            self.cell(0, 8, line.encode('latin-1', 'replace').decode('latin-1'), 0, 1, fill=True)
        self.ln(4)

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
