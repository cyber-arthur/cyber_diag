import requests

def hunter_search(domain, api_key):
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        emails = []
        for item in data.get("data", {}).get("emails", []):
            emails.append({
                "email": item.get("value"),
                "first_name": item.get("first_name"),
                "last_name": item.get("last_name"),
                "position": item.get("position"),
                "phone_number": item.get("phone_number"),
                "confidence": item.get("confidence"),
                "sources": item.get("sources")
            })
        return emails
    else:
        return {"error": response.text}
