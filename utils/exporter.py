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
    skip = ['missing api key','coded by','searching','exception','captcha','error']
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

def generate_ports_chart(ips_data: dict, output_dir: str, siren:str) -> list[str]:
    charts = []
    for ip, data in ips_data.items():
        counts = Counter()
        for line in data.get('nmap', '').splitlines():
            m = re.match(r"(\d+)/tcp", line)
            if m:
                counts[int(m.group(1))] += 1

        if not counts:
            continue

        ports, occ = zip(*sorted(counts.items()))
        plt.figure(figsize=CHART_SIZE)
        bars = plt.barh([str(p) for p in ports], occ, color='#003366')
        plt.xlabel("Occurrences")
        plt.ylabel("Port TCP")
        plt.title(f"Ports pour {ip}", color="#476788")
        plt.tight_layout()
        for bar in bars:
            w = bar.get_width()
            plt.text(w + 0.2, bar.get_y() + bar.get_height()/2, str(int(w)), va='center', fontsize=8)

        safe_ip = ip.replace('.', '_')
        path = os.path.join(output_dir, f"nmap_ports_{siren}_{safe_ip}.png")
        plt.savefig(path)
        plt.close()
        charts.append(path)
    return charts


def generate_vt_pie_chart(stats: dict, output_dir: str, siren: str, domain: str) -> str | None:
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
    safe_domain = re.sub(r'\W+', '_', domain)  # pour éviter caractères problématiques
    path = os.path.join(output_dir, f"vt_pie_{siren}_{safe_domain}.png")
    plt.savefig(path)
    plt.close()
    return path

# ================== PDF Class ==================

class PDF(FPDF):
    def __init__(self):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.add_font("DejaVu", "", "../fonts/DejaVuSans.ttf", uni=True)
        self.set_font("DejaVu", "", 10)
        self.set_auto_page_break(auto=True, margin=15)
        self.set_title("Rapport de Diagnostic Cybersécurité")
        self.set_author("Cyber SES")

    def sanitize(self, t: str) -> str:
        return t or ""

    def header(self):
        if self.page_no() > 2:
            self.set_font("DejaVu", 'B', 12)
            self.set_text_color(*CORPORATE_COLOR)
            self.cell(0, 6, "Cyber SES Sécurisation TPE/PME", ln=1, align='R')
            y = self.get_y()
            self.set_draw_color(*CORPORATE_COLOR)
            self.line(10, y, self.w-10, y)
            self.ln(2)

    def footer(self):
        if self.page_no() > 2:
            self.set_y(-15)
            self.set_font("DejaVu", '', 8)
            self.set_text_color(128)
            self.cell(0, 10, f"Page {self.page_no()}", align='C')

    def toc_page(self, sections: list):
        self.add_page()
        self.set_font("DejaVu", 'B', 18)
        self.set_text_color(*CORPORATE_COLOR)
        self.cell(0, 10, "Table des matières", ln=1, align='C')
        self.ln(4)
        self.set_font("DejaVu", '', 12)
        self.set_text_color(0)
        for i, sec in enumerate(sections, 1):
            self.cell(0, 8, f"{i}. {sec}", ln=1)
        self.ln(2)

    def section_title(self, title: str):
        self.ln(4)
        self.set_font("DejaVu", 'B', 14)
        self.set_text_color(*CORPORATE_COLOR)
        self.cell(0, 8, title, ln=1)
        self.set_text_color(0)

    def subsection_title(self, title: str):
        self.set_font("DejaVu", 'B', 12)
        self.set_text_color(80)
        self.ln(2)
        self.cell(0, 6, title, ln=1)
        self.set_text_color(0)

    def section_text(self, text: str):
        self.set_font("DejaVu", '', 10)
        self.multi_cell(0, 5, text)
        self.ln(1)

    def add_image(self, img_path: str, w: int = 100):
        if os.path.exists(img_path):
            self.image(img_path, w=w)
            self.ln(5)


# ================== Export PDF ==================

def export_pdf(grouped_results: list[tuple[str, dict]], siren: str, output_dir: str, ips_scan: dict):
    pdf = PDF()
    sections = [
        "Résumé",
        "Informations sur l'entreprise",
        "WHOIS & Domaine",
        "Certificat SSL/TLS",
        "Headers HTTP",
        "Emails détectés",
        "Résultat theHarvester",
        "DNS Records",
        "Diagramme VirusTotal",
        "Scraping site web",
        "Scans IP",
        "Ports détectés"
    ]
    
    pdf.toc_page(sections)

    for domain, resultats in grouped_results:
        ent    = domain
        vt     = resultats.get("virustotal", {})
        emails = resultats.get("emails", [])
        dns    = resultats.get("dns", {})
        osint  = resultats.get("osint", {})
        scrap  = resultats.get("scraping", {})

        pdf.add_page()
        pdf.section_title(f"Analyse pour {domain}")

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


        # 2. Informations sur l'entreprise
        pdf.section_title("2. Informations sur l'entreprise")
        pappers = resultats.get("pappers", {})
        siege = pappers.get("siege", {})


        def maybe(txt, val): return f"{txt}{val}" if val else None

        lignes = [
            maybe("Forme juridique : ", pappers.get("forme_juridique")),
            maybe("Catégorie entreprise : ", pappers.get("categorie_entreprise")),
            maybe("Exercice : ", pappers.get("forme_exercice")),
            maybe("Capital social : ", f"{pappers.get('capital')} €" if pappers.get("capital") else None),
            maybe("Date immatriculation : ", pappers.get("date_creation_formate")),
            maybe("Activité : ", f"{pappers.get('naf')} — {pappers.get('libelle_naf')}"),
            maybe("Objet social : ", pappers.get("objet_social")),
            maybe("Statut RCS : ", pappers.get("statut_rcs")),
            maybe("Greffe : ", pappers.get("greffe")),
            maybe("N° RCS : ", pappers.get("numero_rcs")),
            maybe("Date immatriculation RCS : ", pappers.get("date_immatriculation_rcs")),
            maybe("TVA intracommunautaire : ", pappers.get("numero_tva_intracommunautaire")),
            maybe("Tranche d'effectif : ", pappers.get("tranche_effectif")),
            maybe("Effectif (estimé) : ", pappers.get("effectif")),
            maybe("Date clôture exercice : ", pappers.get("date_cloture_exercice")),
            maybe("Prochaine clôture prévue : ", pappers.get("prochaine_date_cloture_exercice_formate")),
            maybe("Site Web : ", pappers.get("site_web")),
            maybe("Téléphone : ", pappers.get("telephone"))
        ]

        adresse = " ".join(
            str(s) for s in filter(None, [
                siege.get("numero_voie"),
                siege.get("type_voie"),
                siege.get("libelle_voie"),
                siege.get("code_postal"),
                siege.get("ville")
            ])
        )
        if adresse.strip():
            lignes.append("Adresse siège : " + adresse)

        if siege.get("complement_adresse"):
            lignes.append(f"Complément d’adresse : {siege['complement_adresse']}")

        if siege.get("latitude") and siege.get("longitude"):
            lignes.append(f"Coordonnées GPS : {siege['latitude']}, {siege['longitude']}")

        if pappers.get("dernier_traitement"):
            lignes.append("Dernière mise à jour : " + pappers["dernier_traitement"])

        # Convention collective
        conventions = pappers.get("conventions_collectives", [])
        for conv in conventions:
            nom = conv.get("nom")
            if nom:
                lignes.append("Convention collective : " + nom)

        # Dirigeants
        dirigeants = pappers.get("dirigeants") or pappers.get("representants") or []
        if dirigeants:
            lignes.append("Dirigeants :")
            for d in dirigeants:
                nom = d.get("nom", "")
                prenom = d.get("prenom", "")
                qualite = d.get("qualite") or d.get("fonction") or ""
                date = d.get("date_debut_mandat")
                ligne = f"  - {prenom} {nom} ({qualite})"
                if date:
                    ligne += f" — depuis {date}"
                lignes.append(ligne)

        # Statuts déposés
        statuts = pappers.get("derniers_statuts")
        if statuts and statuts.get("date_depot_formate"):
            lignes.append("Derniers statuts déposés : " + statuts["date_depot_formate"])

        # Affichage
        if lignes:
            for l in lignes:
                if l:
                    pdf.section_text(l)
        else:
            pdf.section_text("Aucune information d'entreprise disponible.")

        # 3. WHOIS & Domaine
        pdf.section_title("3. WHOIS & Domaine")
        who = vt.get("whois", {})
        pdf.section_text(f"Registrar    : {who.get('registrar','N/A')}")
        pdf.section_text(f"Création     : {who.get('creation_date','N/A')}")
        pdf.section_text(f"Expiration   : {who.get('expiration_date','N/A')}")

        # 4. Certificat SSL/TLS
        pdf.section_title("4. Certificat SSL/TLS")
        cert = fetch_certificate_info(ent)
        pdf.section_text(f"Émetteur    : {cert['issuer']}")
        pdf.section_text(f"Sujet       : {cert['subject']}")
        pdf.section_text(f"Valide du   : {cert['not_before']}")
        pdf.section_text(f"au          : {cert['not_after']}")

        # 5. Headers HTTP
        pdf.section_title("5. Headers HTTP")
        hdr = fetch_http_headers(ent)
        if hdr:
            for k in ['Server','X-Frame-Options','Strict-Transport-Security','Content-Security-Policy']:
                v = hdr.get(k)
                if v:
                    pdf.section_text(f"{k}: {v}")
        else:
            pdf.section_text("Aucun header HTTP récupéré.")

        # 6. Emails détectés
        pdf.section_title("6. Emails détectés")

        if emails:
            for idx, e in enumerate(emails, 1):
                pdf.subsection_title(f"{idx}. {e.get('email', 'Inconnu')} ({e.get('confidence', 'N/C')}%)")

                # Source(s) et domaines
                sources = e.get("sources") or e.get("source") or []
                if isinstance(sources, list):
                    domaines = [s.get("domain") for s in sources if isinstance(s, dict) and s.get("domain")]
                    urls = [s.get("uri") for s in sources if isinstance(s, dict) and s.get("uri")]
                    full_sources = [f"- {d} ({u})" for d, u in zip(domaines, urls)]
                    if full_sources:
                        pdf.section_text("Sources :\n" + "\n".join(full_sources))
                    else:
                        pdf.section_text("Sources : Hunter.io")
                elif isinstance(sources, str):
                    pdf.section_text(f"Source : {sources}")

                # SPF
                spf = e.get("SPF")
                if spf:
                    pdf.section_text(f"SPF : {spf}")

                # DKIM
                dkim = e.get("DKIM")
                if isinstance(dkim, dict):
                    dkim_lines = [f"{k}: {v}" for k, v in dkim.items()]
                    pdf.section_text("DKIM :\n" + "\n".join(dkim_lines))
                elif isinstance(dkim, str):
                    pdf.section_text(f"DKIM : {dkim}")

                # Vérification technique (Hunter Verifier API)
                verif = e.get("verification_details", {})
                if verif:
                    pdf.section_text("Vérification technique :")
                    for k, v in verif.items():
                        etat = "Oui" if v is True else "Non" if v is False else str(v)
                        pdf.section_text(f"  - {k.replace('_', ' ').capitalize()} : {etat}")

                pdf.ln(1)  # espace entre les emails
        else:
            pdf.section_text("Aucun email détecté.")

        # 7. Résultat theHarvester
        pdf.section_title("7. Résultat theHarvester")
        harvest = resultats.get("osint", {})
        texte = harvest.get("texte", "").strip()
        if texte:
            contenu = clean_osint_text(texte)
            if contenu:
                pdf.section_text(contenu)
            else:
                pdf.section_text("Aucun champ intéressant extrait.")
        else:
            pdf.section_text("Aucune donnée récupérée depuis theHarvester.")

        # 8. DNS Records
        pdf.section_title("8. DNS Records")
        for idx, (k, vals) in enumerate(dns.items(), 1):
            vals_str = ', '.join(vals) if isinstance(vals,(list,tuple)) else vals
            pdf.section_text(f"{idx}. {k}: {vals_str}")
            
        # 9. Analyse de sécurité VirusTotal
        pdf.section_title("9. Analyse de sécurité VirusTotal")
    
        pie = generate_vt_pie_chart(stats, output_dir, siren, ent)
        if pie:
            pdf.add_image(pie, w=120)
    
            results = vt.get("results", {})  # Détails par moteur
            malicious_engines = [k for k, v in results.items() if v.get("category") == "malicious"]
            suspicious_engines = [k for k, v in results.items() if v.get("category") == "suspicious"]
            harmless_engines   = [k for k, v in results.items() if v.get("category") == "harmless"]
    
            # Analyse texte
            if malicious_engines:
                pdf.section_text("Menaces détectées : Certains moteurs ont détecté le domaine comme malveillant.")
                pdf.section_text(f"  - {len(malicious_engines)} moteur(s) concerné(s) :")
                for e in malicious_engines:
                    label = results[e].get("result") or "Risque détecté"
                    pdf.section_text(f"     - {e}: {label}")
    
            if suspicious_engines:
                pdf.section_text("Comportements suspects : Certains moteurs trouvent ce domaine suspect.")
                pdf.section_text(f"  - {len(suspicious_engines)} moteur(s) concerné(s) :")
                for e in suspicious_engines:
                    label = results[e].get("result") or "Comportement suspect"
                    pdf.section_text(f"     - {e}: {label}")
    
            if harmless_engines and not malicious_engines and not suspicious_engines:
                pdf.section_text("Aucune menace détectée : Tous les moteurs ont classé ce domaine comme sûr.")
    
            total = sum(stats.values())
            pdf.section_text(f"\nNombre total d'antivirus analysés : {total}")
    
            reputation = vt.get("reputation", 0)
            if reputation > 0:
                pdf.section_text(f"Réputation générale : Bonne ({reputation})")
            elif reputation < 0:
                pdf.section_text(f"Réputation générale : Mauvaise ({reputation})")
            else:
                pdf.section_text(f"Réputation générale : Neutre ({reputation})")
    
        else:
            pdf.section_text("Aucune donnée VirusTotal disponible pour ce domaine.")

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
                
    pdf.add_page()

    # 11. Scans IP
    pdf.section_title("11. Scans IP")
    for idx, (ip, data) in enumerate(ips_scan.items(), 1):
        pdf.subsection_title(f"{idx}. {ip}")
        pdf.section_text(data.get("nmap","").strip() or "Pas de résultat Nmap.")

    # 12. Ports détectés
    pdf.section_title("12. Ports détectés")
    charts = generate_ports_chart(ips_scan, output_dir, siren)
    if charts:
        for c in charts:
            pdf.add_image(c, w=160)
    else:
        pdf.section_text("Aucun port détecté.")

# Enregistrement
    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, f"diag_{siren}.pdf")
    pdf.output(out)
    print(f"Rapport PDF généré : {out}")
