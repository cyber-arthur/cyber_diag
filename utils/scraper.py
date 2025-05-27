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
# Adresses FR classiques (rue, avenue, bd, etc.) avec code postal + ville
ADDRESS_REGEX = re.compile(
    r"\d{1,4}\s+(?:[A-Za-zÀ-ÖØ-öø-ÿ’']+\s?){1,7}\s+"
    r"(?:Street|St|Avenue|Ave|Boulevard|Bd|Road|Rd|Rue|Allée|Impasse|ZAC|BAT)\.?"
    r"[,\s]+\d{5}\s+[A-Za-zÀ-ÖØ-öø-ÿ\-\s]+",
    re.IGNORECASE
)
SOCIAL_DOMAINS = {
    "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "youtube.com", "github.com"
}
# Balises à inspecter pour les noms/prénoms
NAME_TAGS = ['h1', 'h2', 'h3', 'span', 'p']

class SiteScraper:
    def __init__(self, base_url: str, max_pages: int = 500, delay: float = 0.2):
        # Normalisation du domaine (scheme://netloc)
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
        Lance le crawl sur jusqu'à max_pages pages internes,
        extrait emails, téléphones, adresses, noms/prénoms, socials.
        """
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.popleft()
            if url in self.visited:
                continue
            try:
                resp = self.session.get(url, timeout=5)
                content_type = resp.headers.get("Content-Type", "")
                if resp.status_code != 200 or "html" not in content_type:
                    continue
                self.visited.add(url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # 1) extraction brute
                text = soup.get_text(separator=' ')
                self._extract_textual(text)
                
                # 2) extraction dans balises
                self._extract_from_address_tags(soup)
                self._extract_address_from_class(soup)         # nouvelle extraction
                self._extract_microformats_address(soup)
                self._extract_address_lines(soup)
                self._extract_tel_links(soup)
                self._extract_names(soup)
                self._extract_socials(soup)
                
                # 3) liens internes
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
        if p.scheme not in ("http", "https"):
            return None
        if p.netloc.lower() != self.base_netloc:
            return None
        clean = f"{p.scheme}://{p.netloc}{p.path}".rstrip('/')
        return clean

    def _extract_textual(self, text: str):
        """Emails, téléphones, adresses via regex dans le texte brut."""
        for m in EMAIL_REGEX.findall(text):
            self.results['emails'].add(m.strip())
        for m in PHONE_REGEX.findall(text):
            num = re.sub(r"[^\d+]", "", m)
            self.results['phones'].add(num)
        for m in ADDRESS_REGEX.findall(text):
            self.results['addresses'].add(m.strip())

    def _extract_from_address_tags(self, soup: BeautifulSoup):
        """Récupère l’intérieur des <address>…</address>."""
        for tag in soup.find_all('address'):
            txt = tag.get_text(separator=' ', strip=True)
            for m in ADDRESS_REGEX.findall(txt):
                self.results['addresses'].add(m.strip())

    def _extract_address_from_class(self, soup: BeautifulSoup):
        """
        Recherche des adresses dans les blocs dont la classe ou l'id 
        contient 'adresse', souvent utilisé pour les coordonnées postales.
        """
        pattern = re.compile(r'adresse', re.IGNORECASE)
        for el in soup.find_all(attrs={'class': pattern}):
            txt = el.get_text(separator=' ', strip=True)
            for m in ADDRESS_REGEX.findall(txt):
                self.results['addresses'].add(m.strip())
        for el in soup.find_all(attrs={'id': pattern}):
            txt = el.get_text(separator=' ', strip=True)
            for m in ADDRESS_REGEX.findall(txt):
                self.results['addresses'].add(m.strip())

    def _extract_microformats_address(self, soup: BeautifulSoup):
        """
        Recherche les microformats Schema.org PostalAddress
        (<div itemscope itemtype="…PostalAddress">).
        """
        for addr in soup.select('[itemtype*="PostalAddress"]'):
            parts = []
            for prop in ("streetAddress","postalCode","addressLocality"):
                el = addr.select_one(f'[itemprop="{prop}"]')
                if el:
                    parts.append(el.get_text(strip=True))
            if parts:
                self.results['addresses'].add(" ".join(parts))

    def _extract_address_lines(self, soup: BeautifulSoup):
        """
        Parcourt chaque ligne de texte, garde celles contenant
        un code postal et un type de voie (Rue, Av, ZAC, BAT…).
        """
        lines = soup.get_text(separator='\n').split('\n')
        for line in lines:
            if re.search(r'\b\d{5}\b', line) and \
               re.search(r'\b(?:Rue|Av(?:enue)?|Boulevard|Bd|Impasse|Allée|ZAC|BAT)\b',
                         line, re.IGNORECASE):
                cleaned = line.strip()
                if 10 < len(cleaned) < 120:
                    self.results['addresses'].add(cleaned)

    def _extract_tel_links(self, soup: BeautifulSoup):
        """Récupère les liens <a href="tel:…">."""
        for a in soup.select('a[href^="tel:"]'):
            tel = a['href'].split(':',1)[1]
            num = re.sub(r"[^\d+]", "", tel)
            if len(re.sub(r"\D", "", num)) >= 8:
                self.results['phones'].add(num)

    def _extract_names(self, soup: BeautifulSoup):
        for tag in NAME_TAGS:
            for el in soup.find_all(tag):
                txt = el.get_text(strip=True)
                words = txt.split()
                if 1 < len(words) <= 3 and all(w and w[0].isupper() for w in words):
                    # on élimine les titres génériques
                    if not re.search(r'\b(Page|Retour|Découvrez|Télécharger|Recrutements)\b', txt, re.IGNORECASE):
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
        """Ajoute les liens internes non visités à la queue."""
        for a in soup.find_all('a', href=True):
            norm = self._normalize(a['href'], current_url)
            if norm and norm not in self.visited and norm not in self.to_visit:
                self.to_visit.append(norm)
