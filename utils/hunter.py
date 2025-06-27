import requests
import dns.resolver

import dns.resolver

def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = ''.join(s.decode() for s in rdata.strings)
            if txt.startswith('v=spf1'):
                return txt
    except Exception as e:
        return f"Erreur SPF: {str(e)}"
    return "SPF non trouvé"

def get_dkim(domain, selectors=None):
    if selectors is None:
        selectors = ['default', 'selector1', 'google', 'mail']
    for selector in selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                txt = ''.join(s.decode() for s in rdata.strings)
                if txt.startswith('v=DKIM1'):
                    return f"{selector}: {txt}"
        except Exception:
            continue
    return "DKIM non trouvé"

def hunter_search(domain, api_key):
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        emails = []
        spf = get_spf(domain)
        dkim = get_dkim(domain)
        for item in data.get("data", {}).get("emails", []):
            emails.append({
                "email": item.get("value"),
                "first_name": item.get("first_name"),
                "last_name": item.get("last_name"),
                "position": item.get("position"),
                "phone_number": item.get("phone_number"),
                "confidence": item.get("confidence"),
                "sources": item.get("sources"),
                "SPF": spf,
                "DKIM": dkim
            })
        return emails
    else:
        return {"error": response.text}

def enrich_emails(emails: list[str]) -> list[dict]:
    import os
    import requests

    API_KEY = os.getenv("HUNTER_API_KEY")
    endpoint = "https://api.hunter.io/v2/email-verifier"
    enriched = []

    for email in emails:
        try:
            resp = requests.get(endpoint, params={"email": email, "api_key": API_KEY})
            data = resp.json().get("data", {})
            result = {
                "email": email,
                "confidence": data.get("score", 0),
                "source": ["Hunter.io"],
                "SPF": "Non renseigné",
                "DKIM": "Non renseigné",
                "whois": None
            }
            enriched.append(result)
        except Exception:
            enriched.append({
                "email": email,
                "confidence": "N/C",
                "source": ["Hunter.io"]
            })
    return enriched
