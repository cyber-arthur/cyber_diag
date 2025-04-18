def export_txt(resultats, siren):
    txt_path = f"diag_{siren}.txt"
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"📄 Rapport de Diagnostic - {resultats['entreprise']} ({siren})\n")
        f.write("=" * 60 + "\n\n")
        f.write("🧠 DNS Lookup:\n")
        for k, v in resultats["resultats"]["dns"].items():
            f.write(f"  - {k}: {', '.join(v) if v else 'Aucune donnée'}\n")
        f.write("\n")
        f.write("🖥️ Scans IP:\n")
        for ip, data in resultats["resultats"]["ips"].items():
            f.write(f"🔹 IP: {ip}\n")
            f.write("  🔸 Nmap:\n")
            f.write("    " + data["nmap"].replace("\n", "\n    ") + "\n")
            f.write("  🔸 Shodan:\n")
            for key, val in data["shodan"].items():
                f.write(f"    - {key}: {val}\n")
            f.write("\n")
        f.write("🔎 OSINT (theHarvester):\n")
        osint_text = resultats["resultats"]["osint"].get("texte", "")[:5000]
        f.write(osint_text + "\n\n")
        f.write("📬 Emails collectés (Hunter.io):\n")
        for email in resultats["resultats"].get("emails", []):
            f.write(f"  - {email.get('email')} ({email.get('position') or 'poste inconnu'})")
            if email.get("phone_number"):
                f.write(f" 📞 {email.get('phone_number')}")
            f.write("\n")
        if not resultats["resultats"].get("emails"):
            f.write("  Aucun email trouvé.\n")
    print(f"📁 Rapport texte généré : {txt_path}")
