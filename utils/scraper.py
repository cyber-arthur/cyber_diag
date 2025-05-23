import re
import requests
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from bs4 import BeautifulSoup

# ================== Patterns ==================
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_REGEX = re.compile(r"\+?\d[\d\s\.\-]{7,}\d")
ADDRESS_REGEX = re.compile(
    r"\d{1,4}\s+(?:[A-Za-zÀ-ÖØ-öø-ÿ']+\s?){1,5}\s+"
    r"(?:Street|St|Avenue|Ave|Boulevard|Bd|Road|Rd|Rue|Allée|Impasse|ZAC)\.?"
    r"[,\s]+\d{5}\s+[A-Za-zÀ-ÖØ-öø-ÿ\- ]+",
    re.IGNORECASE
)
SOCIAL_DOMAINS = {
    "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "youtube.com", "github.com"
}
NAME_TAGS = ['h1', 'h2', 'h3', 'span', 'p']

class SiteScraper:
    def __init__(self, base_url: str, max_pages: int = 500):
        # Normalize base URL
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        parsed = urlparse(base_url)
        self.base_netloc = parsed.netloc.lower()
        self.base_scheme = parsed.scheme
        self.base_url = f"{self.base_scheme}://{self.base_netloc}"
        
        self.max_pages = max_pages
        self.visited = set()
        self.to_visit = deque([self.base_url])
        
        # Results stored as sets to avoid duplicates
        self.results = {
            'emails': set(),
            'phones': set(),
            'addresses': set(),
            'names': set(),
            'socials': set(),
        }
        
        # Session with a sane User-Agent
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SiteScraper/1.0)"
        })

    def scrape(self) -> dict:
        """
        Crawl up to `max_pages` internal HTML pages,
        extract emails, phones, addresses, names, socials.
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
                text = soup.get_text(separator=' ')
                self._extract_textual(text)
                self._extract_names(soup)
                self._extract_socials(soup)
                self._enqueue_links(soup, url)
            except requests.RequestException:
                continue  # skip errors silently

        # Return sorted lists
        return {k: sorted(v) for k, v in self.results.items()}

    def _normalize(self, href: str, base: str) -> str | None:
        """
        Make absolute URL, strip fragment and trailing slash,
        ensure same domain.
        """
        href = urldefrag(href)[0]  # remove fragment
        abs_url = urljoin(base, href)
        p = urlparse(abs_url)
        if p.scheme not in ("http", "https"):
            return None
        if p.netloc.lower() != self.base_netloc:
            return None
        # strip query parameters to reduce duplicates
        clean = f"{p.scheme}://{p.netloc}{p.path.rstrip('/')}"
        return clean

    def _extract_textual(self, text: str):
        """Extract emails, phones, addresses from raw text."""
        for m in EMAIL_REGEX.findall(text):
            self.results['emails'].add(m.strip())
        for m in PHONE_REGEX.findall(text):
            cleaned = re.sub(r"\s+|\.", "", m)
            self.results['phones'].add(cleaned)
        for m in ADDRESS_REGEX.findall(text):
            self.results['addresses'].add(m.strip())

    def _extract_names(self, soup: BeautifulSoup):
        """Heuristic: short capitalized phrases."""
        for tag in NAME_TAGS:
            for el in soup.find_all(tag):
                txt = el.get_text(strip=True)
                words = txt.split()
                if 1 < len(words) <= 3 and all(w[:1].isupper() for w in words):
                    self.results['names'].add(txt)

    def _extract_socials(self, soup: BeautifulSoup):
        """Collect only short profile/company links."""
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            for domain in SOCIAL_DOMAINS:
                if domain in href:
                    norm = self._normalize(href, self.base_url)
                    if norm:
                        # keep only root profile/company URLs (no parameters)
                        if re.match(rf"https?://(?:www\.)?{re.escape(domain)}/[^/?#]+/?$", norm):
                            self.results['socials'].add(norm)
                    break

    def _enqueue_links(self, soup: BeautifulSoup, current_url: str):
        """Enqueue new internal links, normalized."""
        for a in soup.find_all('a', href=True):
            norm = self._normalize(a['href'], current_url)
            if norm and norm not in self.visited:
                self.to_visit.append(norm)
