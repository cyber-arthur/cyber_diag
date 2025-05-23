import re
import time
import requests
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from bs4 import BeautifulSoup

# ================== Patterns ==================
EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[\s\-.]?)?"          # indicatif pays
    r"(?:\(?\d{2,4}\)?[\s\-.]?)?"       # indicatif régional
    r"\d{2,4}(?:[\s\-.]?\d{2,4}){1,3}"  # numéro local
)
# On autorise désormais jusqu’à 7 mots pour la voie
ADDRESS_REGEX = re.compile(
    r"\d{1,4}\s+(?:[A-Za-zÀ-ÖØ-öø-ÿ']+\s?){1,7}\s+"
    r"(?:Street|St|Avenue|Ave|Boulevard|Bd|Road|Rd|Rue|Allée|Impasse|ZAC)\.?"
    r"[,\s]+\d{5}\s+[A-Za-zÀ-ÖØ-öø-ÿ\- ]+",
    re.IGNORECASE
)
SOCIAL_DOMAINS = {
    "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "youtube.com", "github.com"
}
NAME_TAGS = ['h1', 'h2', 'h3', 'span', 'p', 'li']

class SiteScraper:
    def __init__(self, base_url: str, max_pages: int = 500, delay: float = 0.2):
        # Normalize base URL
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        parsed = urlparse(base_url)
        self.base_netloc = parsed.netloc.lower().removeprefix("www.")
        self.base_scheme = parsed.scheme
        self.base_url = f"{self.base_scheme}://{self.base_netloc}"
        
        self.max_pages = max_pages
        self.delay     = delay
        self.visited   = set()
        self.to_visit  = deque([self.base_url])
        
        self.results = {
            'emails':    set(),
            'phones':    set(),
            'addresses': set(),
            'names':     set(),
            'socials':   set(),
        }
        
        # Session avec User-Agent réaliste
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SiteScraper/2.0)"
        })

    def scrape(self) -> dict:
        """
        Crawl jusqu'à max_pages pages, extrait emails, phones, addresses, names, socials.
        """
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.popleft()
            if url in self.visited:
                continue
            try:
                resp = self.session.get(url, timeout=5)
                ct = resp.headers.get("Content-Type","")
                if resp.status_code != 200 or "html" not in ct:
                    continue
                self.visited.add(url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # 1) extraction brute
                text = soup.get_text(separator=' ')
                self._extract_textual(text)
                
                # 2) extraction plus structurée
                self._extract_from_address_tags(soup)
                self._extract_structured_addresses(soup)
                self._extract_tel_links(soup)
                self._extract_names(soup)
                self._extract_socials(soup)
                
                # 3) suivre les liens internes
                self._enqueue_links(soup, url)
                
                time.sleep(self.delay)
            except requests.RequestException:
                continue

        # Retourne des listes triées
        return {k: sorted(v) for k, v in self.results.items()}

    def _normalize(self, href: str, base: str) -> str | None:
        href = urldefrag(href)[0]
        abs_url = urljoin(base, href)
        p = urlparse(abs_url)
        if p.scheme not in ("http","https"):
            return None
        if p.netloc.lower().removeprefix("www.") != self.base_netloc:
            return None
        # strip query & trailing slash
        clean = f"{p.scheme}://{p.netloc}{p.path}".rstrip('/')
        return clean

    def _extract_textual(self, text: str):
        """Emails, téléphones, adresses dans le texte brut."""
        for m in EMAIL_REGEX.findall(text):
            self.results['emails'].add(m.strip())
        for m in PHONE_REGEX.findall(text):
            num = re.sub(r"[^\d+]", "", m)
            if len(re.sub(r"\D","",num)) >= 8:
                self.results['phones'].add(num)
        for m in ADDRESS_REGEX.findall(text):
            self.results['addresses'].add(m.strip())

    def _extract_from_address_tags(self, soup: BeautifulSoup):
        """<address>…</address>"""
        for addr in soup.find_all('address'):
            txt = addr.get_text(separator=' ', strip=True)
            for m in ADDRESS_REGEX.findall(txt):
                self.results['addresses'].add(m.strip())

    def _extract_structured_addresses(self, soup: BeautifulSoup):
        """
        Microdata/schema.org PostalAddress ou itemprop dans le HTML.
        """
        # recherche d'itemscope itemtype PostalAddress
        for node in soup.find_all(attrs={"itemtype": re.compile("PostalAddress")}):
            street = node.find(attrs={"itemprop":"streetAddress"})
            postal = node.find(attrs={"itemprop":"postalCode"})
            locality = node.find(attrs={"itemprop":"addressLocality"})
            parts = []
            if street:
                parts.append(street.get_text(strip=True))
            if postal or locality:
                cv = ""
                if postal:
                    cv += postal.get_text(strip=True)
                if locality:
                    cv += " " + locality.get_text(strip=True)
                parts.append(cv.strip())
            if parts:
                full = ", ".join(parts)
                self.results['addresses'].add(full)
        # fallback : chercher <span class="street-address"> etc.
        for span in soup.select(".street-address, .postal-code, .address-locality"):
            txt = span.get_text(strip=True)
            if len(txt)>4 and re.search(r"\d", txt):
                self.results['addresses'].add(txt)

    def _extract_tel_links(self, soup: BeautifulSoup):
        """liens <a href="tel:...">"""
        for a in soup.select('a[href^="tel:"]'):
            tel = a['href'].split(':',1)[1]
            num = re.sub(r"[^\d+]", "", tel)
            if len(re.sub(r"\D","",num)) >= 8:
                self.results['phones'].add(num)

    def _extract_names(self, soup: BeautifulSoup):
        """Phrases courtes capitalisées (2–4 mots)."""
        stopwords = {"Copyright","©","All rights reserved","Mentions","Contact","Email"}
        for tag in NAME_TAGS:
            for el in soup.find_all(tag):
                txt = el.get_text(strip=True)
                if any(sw in txt for sw in stopwords):
                    continue
                words = txt.split()
                if 1 < len(words) <= 4 and all(w[0].isupper() for w in words):
                    self.results['names'].add(txt)

    def _extract_socials(self, soup: BeautifulSoup):
        """Liens courts vers réseaux sociaux."""
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            for domain in SOCIAL_DOMAINS:
                if domain in href:
                    norm = self._normalize(href, self.base_url)
                    if norm and re.match(
                        rf"https?://(?:www\.)?{re.escape(domain)}/[^/?#]+/?$", norm
                    ):
                        self.results['socials'].add(norm)
                    break

    def _enqueue_links(self, soup: BeautifulSoup, current_url: str):
        """Ajoute à la file les liens internes normalisés."""
        for a in soup.find_all('a', href=True):
            norm = self._normalize(a['href'], current_url)
            if norm and norm not in self.visited and norm not in self.to_visit:
                self.to_visit.append(norm)
