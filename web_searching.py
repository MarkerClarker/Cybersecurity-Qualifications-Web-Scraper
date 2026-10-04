"""A series of functions useful in the Web Scraping aspect of this project."""

#imports Python libraries
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

#the important stuff for web scraping, and HTML parsing, and charting
import requests
from bs4 import BeautifulSoup
from ddgs import DDGS
from ddgs.exceptions import DDGSException
from requests.adapters import HTTPAdapter

from patterns import certification_patterns, extract_matching_terms, skill_patterns

#global variables for tracking success and failure counts
total_success: int = 0
total_fail: int = 0
#locks for thread safety when updating the success and failure counters
_counter_lock = threading.Lock()

#This creates storage for each worker thread
thread_local = threading.local()

def get_worker_session() -> requests.Session:
    """Returns/and creates a requests.Session object for the current worker thread"""
    if not hasattr(thread_local, "session"):
        thread_local.session = create_session()

    return thread_local.session

#This creates a requests.Session object with a connection pool and custom headers to gain access to web pages
def create_session() -> requests.Session:
    """Creates a requests.Session object with a connection pool and custom headers to gain access to web pages."""
    adapter = HTTPAdapter(
        max_retries=0,
        pool_connections=16,
        pool_maxsize=16,
    )

    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,"
            "application/xml;q=0.9,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.5",
    })

    return session

def search_the_web(query: str,max_results: int = 100,) -> list[dict[str, str]]:
    """Searches DDG for a query and returns a list of dictionary of results # with their titles, links, and descriptions"""
    print(f"Searching for: '{query}'...")

    #retires the search up to 3 times if it fails for whatever reason
    for attempt in range(3):
        try:
            with DDGS() as ddgs:
                results = list(
                    ddgs.text(
                        query,
                        max_results=max_results,
                    )
                )

            return results

    #if an error occurs that can be retried, it will print the error 
    # and retry up to 3 times
        except DDGSException as error:
            print(
                f"Search failed for '{query}' "
                f"(attempt {attempt + 1}/3): {error}"
            )

            if attempt < 2:
                time.sleep(2 ** attempt)

    print(f"No results returned for: '{query}'")
    return []


def links_from_search(
    results: list[dict[str, str]],
) -> list[str]:
    """Extracts unique links from the search results, filtering out blocked sites and duplicates, and returns a list of unique links."""
    
    print("Collecting unique links...")

    #list of blocked sites to avoid scraping websites that will always block the script
    blocked_sites = {
        "linkedin.com",
        "indeed.com",
        "glassdoor.com",
        "ziprecruiter.com",
    }

    #creates a list of links and a set of seen links to avoid duplicates
    links: list[str] = []
    seen_links: set[str] = set()

    for result in results:
        #cleans up the href and removes any whitespace
        href = result.get("href", "").strip()

        #ignores any links that are empty or None
        if not href:
            continue

        parsed_url = urlparse(href)
        domain = parsed_url.netloc.lower()

        domain = domain.removeprefix("www.")

        is_blocked = any(
            domain == site or domain.endswith(f".{site}")
            for site in blocked_sites
        )
        #ignore blocked sites and continue to the next
        if is_blocked:
            continue

        #add the link to the list if it hasn't been seen before
        if href not in seen_links:
            seen_links.add(href)
            links.append(href)

    #return the list of unique links
    return links

#cleans up text by replacing common encoding issues and removing extra whitespace
def clean_text(text: str) -> str:
    """Cleans up text by replacing common encoding issues and removing extra whitespace."""
    #a list of things needing replacing in any given string
    replacements = {
        "â€™": "'",
        "â€œ": '"',
        "â€\x9d": '"',
        "â€“": "–",
        "â€”": "—",
        "â€¦": "...",
        "â\x80\x94": "—",
        "â\x80\x99": "'",
        "â\x80\x98": "'",
        "â\x80\x8e": "",
        "Â": "",
    }

    # Replace common encoding issues with their correct characters
    for bad_text, good_text in replacements.items():
        text = text.replace(bad_text, good_text)

    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_qualifications(
    doc: BeautifulSoup,
) -> list[str]:
    """Extracts qualifications from the HTML document and returns a list of cleaned and filtered qualifications."""
    targets: list[str] = []

    #contains keywords to be searched for in headings to identify relevant sections
    target_heading_pattern = re.compile(
        r"""
        certifications?|credentials?|
        qualifications?|requirements?|
        required\s+skills?|preferred\s+skills?|
        technical\s+skills?|technical\s+qualifications?|
        programming|programming\s+languages?|
        tools?|technologies?|platforms?|
        software|education|experience|
        competencies?|knowledge
        """,
        re.IGNORECASE | re.VERBOSE,
    )
    #contains keywords to be searched for in the content to identify relevant sections
    target_content_pattern = re.compile(
        r"""
        certification|certified|credential|
        comptia|security\+|network\+|cysa\+|securityx|
        cissp|cism|ceh|gsec|giac|aws|azure|gcp|
        sc-200|bt[l1]|cdsa|ejpt|

        python|powershell|bash|javascript|java|ruby|perl|
        sql|scripting|programming|api|

        siem|splunk|sentinel|qradar|arcsight|logrhythm|
        incident\s+response|threat\s+hunt|threat\s+intelligence|
        vulnerability|penetration\s+testing|ethical\s+hacking|
        malware|digital\s+forensics|reverse\s+engineering|
        network\s+security|cloud\s+security|application\s+security|
        security\s+monitoring|log\s+analysis|risk\s+management|
        compliance|encryption|iam|identity\s+and\s+access|
        active\s+directory|mitre\s+attack|

        wireshark|tcpdump|zeek|suricata|nessus|qualys|
        nmap|metasploit|burp\s+suite|kali|security\s+onion|
        wazuh|elastic|elasticsearch|kibana|soar|edr|xdr|
        firewall|ids|ips|vpn|linux|windows|

        bachelor|master|associate|degree|diploma|
        years?\s+of\s+experience|hands[- ]on\s+experience|
        communication|problem-solving|problem\s+solving|
        analytical|critical\s+thinking|attention\s+to\s+detail
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    #contains keywords to be searched for to exclude certain sections
    excluded_pattern = re.compile(
        r"""
        responsibility|responsibilities|
        monitor|monitoring|investigate|investigating|
        respond|responding|report|reporting|
        apply\s+now|salary|pay\s+range|benefits?|
        interview\s+question|frequently\s+asked|
        ^what\s+is|^how\s+do\s+you|^why\s+do\s+you|
        read\s+more|learn\s+more|subscribe|
        about\s+us|contact\s+us|competitors?|
        career\s+path|projected\s+employment|
        https?://|www\.|copyright|privacy\s+policy|
        newsletter|article\s+series|this\s+article|
        faq|conclusion|table\s+of\s+contents|
        ^page\s+\d+
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    #heading tags to be searched for in the HTML document
    heading_tags = {
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
    }
    #removes script, style, nav, footer, header, aside, form, and button tags from the HTML document to avoid irrelevant content
    for tag in doc.find_all(
        [
            "script",
            "style",
            "nav",
            "footer",
            "header",
            "aside",
            "form",
            "button",
        ]
    ):
        tag.decompose()

    def clean_item(text: str) -> str:
        """Cleans the text by removing leading bullet points, trailing references, and other unwanted characters."""
        text = clean_text(text)
    # removes leading bullet points, trailing references, and other unwanted characters from the text
        text = re.sub(
            r"^[•●▪◦*–—-]+\s*",
            "",
            text,
        )
        # removes trailing references in the form of (A1234) or [1] from the text
        text = re.sub(
            r"\s*\([A-Z]\d{4}\)\s*$",
            "",
            text,
        )
        # removes trailing references in the form of [1], [2], etc. from the text
        text = re.sub(
            r"\s*\[\d+\]\s*",
            " ",
            text,
        )
        #returns the cleaned text
        return clean_text(text)

    #checks if the text is a good target by checking its length, excluded patterns, and target content patterns
    def is_good_target(text: str) -> bool:
        """Checks if the text is a good target by checking its length, excluded patterns, and target content patterns."""
        text = clean_item(text)

        if not 3 <= len(text) <= 180:
            return False

        if excluded_pattern.search(text):
            return False

        if "?" in text:
            return False

        if "$" in text:
            return False

        if re.search(r"\d+(\.\d+)?%", text):
            return False
        
        # if target content pattern is not found in the text, then
        # it is not a good target, if the target is met, then it 
        # is a good target
        return target_content_pattern.search(text)

    #append the good targets to a list of targets after cleaning the text and checking if it is a good target
    def add_target(text: str) -> None:
        """Appends the good targets to a list of targets after cleaning the text and checking if it is a good target."""
        text = clean_item(text)

        if not is_good_target(text):
            return

        targets.append(text)

    #find all headings in the HTML document and check if they match the target heading pattern, if they do, 
    # then find all list items in the parent and sibling elements and add them to the list of targets
    for heading in doc.find_all(
        ["h1", "h2", "h3", "h4", "h5", "h6"]
    ):
        heading_text = clean_item(
            heading.get_text(" ", strip=True)
        )

        if not target_heading_pattern.search(heading_text):
            continue

        parent = heading.parent

        if parent is not None:
            for item in parent.find_all("li"):
                add_target(
                    item.get_text(" ", strip=True)
                )

        for sibling in heading.find_next_siblings():
            if sibling.name in heading_tags:
                break

            for item in sibling.find_all("li"):
                add_target(
                    item.get_text(" ", strip=True)
                )

    return targets

#fetches a single page and extracts the qualifications from it, returning the link, the extracted records, and a success flag
def fetch_one_page(
    link: str,
) -> tuple[str, list[dict[str, str]], bool]:
    """Fetches a single page and extracts the qualifications from it, returning the link, the extracted records, and a success flag."""
    records: list[dict[str, str]] = []

    # Reuse one session per worker thread.
    session = get_worker_session()

    max_attempts = 3
    retryable_statuses = {
        408, 429, 500, 502, 503, 504,
    }

    for attempt in range(1, max_attempts + 1):
        try:
            response = session.get(
                link,
                timeout=(3, 8),
                allow_redirects=True,
            )

            # Retry temporary server/rate-limit responses.
            if response.status_code in retryable_statuses:
                if attempt < max_attempts:
                    time.sleep(2 ** (attempt - 1))
                    continue

                return link, records, False

            # Does not retry permanent responses such as 403 or 404.
            if response.status_code != 200:
                return link, records, False

            content_type = response.headers.get(
                "Content-Type",
                "",
            ).lower()

            # Ignore PDFs, images, JSON, and other non-HTML files.
            if "text/html" not in content_type:
                return link, records, False
            #parse the text with 
            doc = BeautifulSoup(
                response.text,
                "html.parser",
            )

            page_title = ""

            if doc.title is not None:
                page_title = clean_text(
                    doc.title.get_text(" ", strip=True)
                )
            #declares variable for the extracted qualifications
            page_qualifications = extract_qualifications(doc)

            #appends the extracted qualifications and pages titles and URLs
            # to the records list 
            for qualification in page_qualifications:
                records.append({
                    "qualification": qualification,
                    "source_url": link,
                    "page_title": page_title,
                })

            return link, records, True

        except (
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
        ):
            # Retry timeout and connection errors.
            if attempt < max_attempts:
                time.sleep(2 ** (attempt - 1))
                continue

            return link, records, False

        except requests.exceptions.RequestException:
            # Treat other request errors as failed pages.
            return link, records, False

    return link, records, False


def qualifications_from_search(
    links: list[str],
) -> list[dict[str, str]]:
    """Searches the web for the given links and extracts the qualifications from each page, returning a list of records with the extracted 
    qualifications, source URLs, and page titles and increments the global success and failure counters depending of in the search was 
    successful or not"""
    global total_success, total_fail

    records: list[dict[str, str]] = []
    unique_links = list(dict.fromkeys(links))
    #uses 20 workers for the tasks, this can be adjusted depending on performance needs
    max_workers = 20
    total_links = len(unique_links)
    completed_links = 0
    start_time = time.perf_counter()

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
        futures = [
            executor.submit(fetch_one_page, link)
            for link in unique_links
        ]

        for future in as_completed(futures):
            completed_links += 1

            try:
                _link, page_records, success = future.result()

                if success:
                    with _counter_lock:
                        total_success += 1
                    records.extend(page_records)
                else:
                    with _counter_lock:
                        total_fail += 1

            except requests.exceptions.RequestException:
                with _counter_lock:
                    total_fail += 1

            elapsed = time.perf_counter() - start_time

            status = (
                f"Completed {completed_links}/{total_links} | "
                f"Successful: {total_success} | "
                f"Failed: {total_fail} | "
                #calculates the elapsed time for the users sake if the script hits a snag
                f"Elapsed: {elapsed:.1f}s"
            )

            # \033[K clears the remainder of the current line.
            print(
                f"\r\033[K{status}",
                end="",
                flush=True,
            )

    print()
    return records

def count_terms_once_per_page(
    records: list[dict[str, str]],
) -> tuple[Counter[str], Counter[str]]:
    """Counts certifications and skills, ensuring that each term is only counted once per page, and returns two Counter objects."""
    certification_counts: Counter[str] = Counter()
    skill_counts: Counter[str] = Counter()

    seen_certifications: set[tuple[str, str]] = set()
    seen_skills: set[tuple[str, str]] = set()

    for record in records:
        source_url = record["source_url"]
        qualification = record["qualification"]

        certifications = extract_matching_terms(
            qualification,
            certification_patterns,
        )

        skills = extract_matching_terms(
            qualification,
            skill_patterns,
        )

        for certification in certifications:
            page_certification = (
                source_url,
                certification,
            )

            if page_certification not in seen_certifications:
                seen_certifications.add(page_certification)
                certification_counts[certification] += 1

        for skill in skills:
            page_skill = (
                source_url,
                skill,
            )

            if page_skill not in seen_skills:
                seen_skills.add(page_skill)
                skill_counts[skill] += 1

    return certification_counts, skill_counts