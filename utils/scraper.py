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
# Numéros FR : +33 ou 0X avec groupements en 2 chiffres
PHONE_REGEX = re.compile(
    r"(?:\+33|0)[\s\.\-]?[1-9](?:[\s\.\-]?\d{2}){4}"
)
# Adresses FR étendues
ADDRESS_REGEX = re.compile(
    r"\d{1,4}\s+(?:[A-Za-zÀ-ÖØ-öø-ÿ’']+\s?){1,7}\s+"
    r"(?:Street|St|Avenue|Ave|Boulevard|Bd|Road|Rd|Rue|Allée|Impasse|ZAC)\.?"
    r"[,\s]+\d{5}\s+[A-Za-zÀ-ÖØ-öø-ÿ\-\s]+",
    re.IGNORECASE
)
SOCIAL_DOMAINS = {
    "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "youtube.com", "github.com"
}
# On considère que les vrais noms font 2 mots max, initiale majuscule + minuscule
NAME_REGEX = re.compile(r"^[A-Z][a-z]+(?:\s[A-Z][a-z]+){1,2}$")

# ================== Scraper ==================
class SiteScraper:
    def __init__(self, base_url: str, max_pages: int = 500, delay: float = 0.2):
        # Normalisation du domaine (on garde simplement scheme://netloc)
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        parsed = urlparse(base_url)
        self.base_netloc = parsed.netloc.lower()
        self.base_scheme = parsed.scheme
        self.base_url = f"{self.base_scheme}://{self.base_netloc}"
        
        self.max_pages = max_pages
        self.delay = delay
        self.visited = set()
        self.to_visit = deque([self.base_url])
        
        self.results = {
            'emails': set(),
            'phones': set(),
            'addresses': set(),
            'names': set(),
            'socials': set(),
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SiteScraper/2.0)"
        })

    def scrape(self) -> dict:
        """
        Lance le crawl sur jusqu'à max_pages pages internes.
        """
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.popleft()
            if url in self.visited:
                continue
            try:
                resp = self.session.get(url, timeout=5)
                ct = resp.headers.get("Content-Type", "")
                if resp.status_code != 200 or "html" not in ct:
                    continue
                self.visited.add(url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # 1) Extraction brute dans le texte
                text = soup.get_text(separator=' ')
                self._extract_textual(text)
                
                # 2) Extraction dans balises structurées
                self._extract_from_address_tags(soup)
                self._extract_microformats_address(soup)
                self._extract_tel_links(soup)
                self._extract_names(soup)
                self._extract_socials(soup)
                
                # 3) Enqueue nouveaux liens internes
                self._enqueue_links(soup, url)
                
                time.sleep(self.delay)
            except requests.RequestException:
                continue

        # Retourne des listes triées pour plus de lisibilité
        return {k: sorted(v) for k, v in self.results.items()}

    def _normalize(self, href: str, base: str) -> str | None:
        """
        Absolutise, strip fragment, et assure qu'on reste sur le même domaine.
        """
        href = urldefrag(href)[0]
        abs_url = urljoin(base, href)
        p = urlparse(abs_url)
        if p.scheme not in ("http", "https"):
            return None
        if p.netloc.lower() != self.base_netloc:
            return None
        clean = f"{p.scheme}://{p.netloc}{p.path}".rstrip('/')
        return clean

    def _extract_textual(self, text: str):
        """Emails, téléphones, adresses depuis le texte brut."""
        for m in EMAIL_REGEX.findall(text):
            self.results['emails'].add(m.strip())
        for m in PHONE_REGEX.findall(text):
            num = re.sub(r"[^\d+]", "", m)
            self.results['phones'].add(num)
        for m in ADDRESS_REGEX.findall(text):
            self.results['addresses'].add(m.strip())

    def _extract_from_address_tags(self, soup: BeautifulSoup):
        """Récupère les <address>...</address>."""
        for tag in soup.find_all('address'):
            txt = tag.get_text(separator=' ', strip=True)
            for m in ADDRESS_REGEX.findall(txt):
                self.results['addresses'].add(m.strip())

    def _extract_microformats_address(self, soup: BeautifulSoup):
        """
        Recherche les microformats Schema.org PostalAddress :
        <div itemscope itemtype="http://schema.org/PostalAddress">...
        """
        for addr in soup.select('[itemtype*="PostalAddress"]'):
            parts = []
            # streetAddress, postalCode, addressLocality
            for prop in ["streetAddress","postalCode","addressLocality"]:
                el = addr.select_one(f'[itemprop="{prop}"]')
                if el:
                    parts.append(el.get_text(strip=True))
            if parts:
                self.results['addresses'].add(" ".join(parts))

    def _extract_tel_links(self, soup: BeautifulSoup):
        """Récupère <a href="tel:...">."""
        for a in soup.select('a[href^="tel:"]'):
            tel = a['href'].split(':',1)[1]
            num = re.sub(r"[^\d+]", "", tel)
            if len(re.sub(r"\D", "", num)) >= 8:
                self.results['phones'].add(num)

    def _extract_names(self, soup: BeautifulSoup):
        """
        Heuristique plus stricte : 2 à 3 mots, chacun 
        commençant par Majuscule suivi de minuscules.
        """
        for el in soup.find_all(text=True):
            txt = el.strip()
            if NAME_REGEX.match(txt):
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
        """Ajoute à la queue les liens internes encore non visités."""
        for a in soup.find_all('a', href=True):
            norm = self._normalize(a['href'], current_url)
            if norm and norm not in self.visited and norm not in self.to_visit:
                self.to_visit.append(norm)
