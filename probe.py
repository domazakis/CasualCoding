"""Δοκιμή πηγών αγγελιών από τους servers του GitHub Actions.

Για κάθε πηγή ελέγχει:
  - αν το robots.txt επιτρέπει τη σελίδα (αν δεν την επιτρέπει, ΔΕΝ την ανοίγει)
  - κωδικό απόκρισης, μέγεθος, χρόνο
  - σημάδια μπλοκαρίσματος (Cloudflare, captcha, access denied)
  - πόσες αγγελίες βρίσκει στο HTML (με βάση το μοτίβο των συνδέσμων τους)
  - δείγμα τίτλων, τίτλο σελίδας
Για τις σελίδες αγγελίας ψάχνει και πώς γίνεται η αίτηση (εξωτερικός σύνδεσμος, email).
Για jobfind και skywalker καταγράφει και τις φόρμες/τα API που φαίνονται στη σελίδα,
ώστε να βρούμε τη σωστή διεύθυνση αναζήτησης.

Γράφει results/probe-latest.md και results/probe-latest.json.
"""

import json
import re
import sys
import time
import urllib.parse
import urllib.robotparser
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)
HEADERS = {
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
    "Accept-Language": "el-GR,el;q=0.9,en;q=0.8",
}
TIMEOUT = 25
PAUSE = 2.0  # δευτερόλεπτα ανάμεσα στα αιτήματα, για ευγένεια

BLOCK_SIGNS = [
    "just a moment",
    "cf-chl",
    "challenge-platform",
    "captcha",
    "access denied",
    "pardon our interruption",
    "are you a robot",
    "request blocked",
    "unusual traffic",
]

q = urllib.parse.quote

# (πηγή, περιγραφή, url, regex για τα links αγγελιών, είδος)
# είδος: "list" = σελίδα αποτελεσμάτων, "detail" = σελίδα μίας αγγελίας,
#        "discover" = σελίδα όπου ψάχνουμε φόρμες/API, "api" = JSON
TESTS = [
    # kariera.gr
    ("kariera", "αναζήτηση events", "https://www.kariera.gr/jobs?title=events&location=Athens", r"/jobs/[a-z0-9-]+/(\d{5,})", "list"),
    ("kariera", "αναζήτηση επικοινωνία", f"https://www.kariera.gr/jobs?title={q('επικοινωνία')}&location=Athens", r"/jobs/[a-z0-9-]+/(\d{5,})", "list"),
    ("kariera", "αναζήτηση events σελ. 2 (page=2)", "https://www.kariera.gr/jobs?title=events&location=Athens&page=2", r"/jobs/[a-z0-9-]+/(\d{5,})", "list"),
    ("kariera", "κατηγορία PR", "https://www.kariera.gr/en/jobs/public-relations-jobs", r"/jobs/[a-z0-9-]+/(\d{5,})", "list"),
    ("kariera", "κατηγορία marketing", "https://www.kariera.gr/en/jobs/marketing-or-advertising-jobs", r"/jobs/[a-z0-9-]+/(\d{5,})", "list"),
    ("kariera", "κατηγορία marketing σελ. 2", "https://www.kariera.gr/en/jobs/marketing-or-advertising-jobs?page=2", r"/jobs/[a-z0-9-]+/(\d{5,})", "list"),
    ("kariera", "σελίδα αγγελίας (Head of Communications, XM)", "https://www.kariera.gr/jobs/marketing-or-advertising-jobs/347561", None, "detail"),
    # Indeed
    ("indeed", "αναζήτηση events, 2 ημέρες", f"https://gr.indeed.com/jobs?q=events&l={q('Αθήνα')}&sort=date&fromage=2", r"(?:jk=|data-jk=\")([0-9a-f]{16})", "list"),
    ("indeed", "αναζήτηση επικοινωνία, 2 ημέρες", f"https://gr.indeed.com/jobs?q={q('επικοινωνία')}&l={q('Αθήνα')}&sort=date&fromage=2", r"(?:jk=|data-jk=\")([0-9a-f]{16})", "list"),
    ("indeed", "RSS events", f"https://gr.indeed.com/rss?q=events&l={q('Αθήνα')}&sort=date", r"jk=([0-9a-f]{16})", "list"),
    # Jooble
    ("jooble", "events Αθήνα", "https://gr.jooble.org/%CE%B5%CF%81%CE%B3%CE%B1%CF%83%CE%AF%CE%B1-%CE%BF%CF%81%CE%B3%CE%AC%CE%BD%CF%89%CF%83%CE%B7-events/%CE%91%CE%B8%CE%AE%CE%BD%CE%B1", r"/r?jdp/(-?\d{6,})", "list"),
    ("jooble", "υπεύθυνος επικοινωνίας", "https://gr.jooble.org/%CE%B5%CF%81%CE%B3%CE%B1%CF%83%CE%AF%CE%B1-%CF%85%CF%80%CE%B5%CF%8D%CE%B8%CF%85%CE%BD%CE%BF%CF%82-%CE%B5%CF%80%CE%B9%CE%BA%CE%BF%CE%B9%CE%BD%CF%89%CE%BD%CE%AF%CE%B1%CF%82", r"/r?jdp/(-?\d{6,})", "list"),
    ("jooble", "events Αθήνα σελ. 2 (p=2)", "https://gr.jooble.org/%CE%B5%CF%81%CE%B3%CE%B1%CF%83%CE%AF%CE%B1-%CE%BF%CF%81%CE%B3%CE%AC%CE%BD%CF%89%CF%83%CE%B7-events/%CE%91%CE%B8%CE%AE%CE%BD%CE%B1?p=2", r"/r?jdp/(-?\d{6,})", "list"),
    ("jooble", "σελίδα αγγελίας (Event Project Manager, linq)", "https://gr.jooble.org/jdp/1397376058319422201", None, "detail"),
    # jobfind.gr
    ("jobfind", "Αθήνα χωρίς φίλτρο (σελίδα + φόρμες)", "https://www.jobfind.gr/JobAds/all/Athens/GR/Theseis_Ergasias", r"/JobAd/View/GR/Theseis_Ergasias/([0-9a-fA-F-]{36})", "discover"),
    ("jobfind", "keywords=events", "https://www.jobfind.gr/JobAds/all/Athens/GR/Theseis_Ergasias?keywords=events", r"/JobAd/View/GR/Theseis_Ergasias/([0-9a-fA-F-]{36})", "list"),
    ("jobfind", "keyword=events", "https://www.jobfind.gr/JobAds/all/Athens/GR/Theseis_Ergasias?keyword=events", r"/JobAd/View/GR/Theseis_Ergasias/([0-9a-fA-F-]{36})", "list"),
    ("jobfind", "q=events", "https://www.jobfind.gr/JobAds/all/Athens/GR/Theseis_Ergasias?q=events", r"/JobAd/View/GR/Theseis_Ergasias/([0-9a-fA-F-]{36})", "list"),
    ("jobfind", "/JobAds/Search?keywords=events", "https://www.jobfind.gr/JobAds/Search?keywords=events", r"/JobAd/View/GR/Theseis_Ergasias/([0-9a-fA-F-]{36})", "list"),
    # skywalker.gr
    ("skywalker", "σελίδα αγγελιών (σελίδα + scripts/API)", "https://www.skywalker.gr/el/aggelies-ergasias", r"/el/aggelia-ergasias/[^\"'\s]*?(\d{4,})", "discover"),
    ("skywalker", "keywords=events", "https://www.skywalker.gr/el/aggelies-ergasias?keywords=events", r"/el/aggelia-ergasias/[^\"'\s]*?(\d{4,})", "list"),
    # Workable (δημόσια μηχανή αναζήτησης θέσεων)
    ("workable", "αναζήτηση communications Αθήνα", "https://jobs.workable.com/search?location=Athens&query=communications", r"/view/([A-Za-z0-9]{6,})", "list"),
    ("workable", "API communications Αθήνα", "https://jobs.workable.com/api/v1/jobs?query=communications&location=Athens", r"\"id\"\s*:\s*\"([A-Za-z0-9-]{6,})\"", "api"),
    # Careerjet
    ("careerjet", "events Αθήνα", f"https://www.careerjet.gr/jobs?s=events&l={q('Αθήνα')}", r"/jobad/([a-z0-9]{10,})", "list"),
    # Ιδρύματα / προκηρύξεις
    ("onassis", "smartcv", "https://apply.smartcv.co/onassis-group/", r"/onassis-group/job/(\w+)", "list"),
    ("snf", "job openings", "https://www.snf.org/en/about/career-opportunities/job-openings/", r"job-openings/([a-z0-9-]{4,})", "list"),
    ("alfavita", "εργασία", "https://www.alfavita.gr/ergasia", r"/ergasia/(\d{6})_", "list"),
    ("proson", "προκηρύξεις", "https://www.proson.gr/ergasia/prokiryxeis", r"/ergasia/prokiryxeis/(\d+)_", "list"),
    # Μόνο έλεγχος robots.txt — δεν ανοίγονται αν απαγορεύονται
    ("linkedin", "guest αναζήτηση (μόνο αν επιτρέπεται)", "https://www.linkedin.com/jobs/search?keywords=communications&location=Athens", r"/jobs/view/[^\"']*?(\d{8,})", "list"),
    ("xe", "αγγελίες εργασίας (μόνο αν επιτρέπεται)", "https://www.xe.gr/ergasia/", r"/ergasia/[^\"']*?(\d{6,})", "list"),
]

APPLY_HINTS = re.compile(
    r"(workable\.com|smartcv\.co|greenhouse\.io|lever\.co|teamtailor|recruitee|bamboohr|"
    r"forms\.gle|docs\.google\.com/forms|apply|aitisi|αίτηση|careers?)",
    re.I,
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

session = requests.Session()
session.headers.update(HEADERS)
robots_cache: dict[str, tuple[str, urllib.robotparser.RobotFileParser | None]] = {}


def robots_for(url: str):
    p = urllib.parse.urlsplit(url)
    root = f"{p.scheme}://{p.netloc}"
    if root in robots_cache:
        return robots_cache[root]
    rp = urllib.robotparser.RobotFileParser()
    try:
        r = session.get(root + "/robots.txt", timeout=TIMEOUT)
        if r.status_code in (401, 403):
            rp.disallow_all = True
            note = f"robots.txt HTTP {r.status_code} (θεωρείται απαγόρευση)"
        elif r.status_code >= 400:
            rp.allow_all = True
            note = f"robots.txt HTTP {r.status_code} (θεωρείται ελεύθερο)"
        else:
            rp.parse(r.text.splitlines())
            note = "robots.txt OK"
    except Exception as e:  # noqa: BLE001
        rp = None
        note = f"robots.txt δεν διαβάστηκε ({type(e).__name__})"
    robots_cache[root] = (note, rp)
    time.sleep(PAUSE)
    return robots_cache[root]


def block_signs(text: str) -> list[str]:
    low = text[:200_000].lower()
    return [s for s in BLOCK_SIGNS if s in low]


def page_title(soup: BeautifulSoup) -> str:
    t = soup.title.string if soup.title and soup.title.string else ""
    return " ".join(t.split())[:160]


def listing_links(html: str, soup: BeautifulSoup, pattern: str, base: str):
    rx = re.compile(pattern)
    ids_raw = set(rx.findall(html))
    samples = []
    seen = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        m = rx.search(href)
        if not m:
            continue
        key = m.group(1)
        text = " ".join(a.get_text(" ", strip=True).split())
        if key in seen or not text:
            continue
        seen.add(key)
        samples.append({"id": key, "title": text[:110], "url": urllib.parse.urljoin(base, href)[:200]})
    return ids_raw, samples


def discover(soup: BeautifulSoup, html: str):
    forms = []
    for f in soup.find_all("form"):
        inputs = [
            (i.get("name"), i.get("type"))
            for i in f.find_all(["input", "select"])
            if i.get("name")
        ]
        forms.append({"action": f.get("action"), "method": f.get("method"), "inputs": inputs[:20]})
    scripts = [s.get("src") for s in soup.find_all("script", src=True)][:30]
    api_hits = sorted(set(re.findall(r"[\"'](/?(?:api|graphql|_next/data)[^\"'\s]{0,120})[\"']", html)))[:30]
    search_links = sorted(
        {a["href"] for a in soup.find_all("a", href=True) if re.search(r"search|keyword|aggelies-ergasias\?", a["href"], re.I)}
    )[:30]
    next_data = bool(soup.find("script", id="__NEXT_DATA__"))
    return {"forms": forms, "scripts": scripts, "api_strings": api_hits, "search_links": search_links, "__NEXT_DATA__": next_data}


def apply_info(soup: BeautifulSoup, html: str, base: str):
    hrefs = []
    for a in soup.find_all("a", href=True):
        h = a["href"]
        t = " ".join(a.get_text(" ", strip=True).split())
        if h.startswith("mailto:") or APPLY_HINTS.search(h) or APPLY_HINTS.search(t):
            hrefs.append({"text": t[:60], "href": urllib.parse.urljoin(base, h)[:200]})
    buttons = [" ".join(b.get_text(" ", strip=True).split())[:60] for b in soup.find_all("button")]
    buttons = [b for b in buttons if APPLY_HINTS.search(b)][:10]
    emails = sorted(set(EMAIL_RE.findall(soup.get_text(" "))))[:10]
    body_len = len(" ".join(soup.get_text(" ").split()))
    return {"apply_links": hrefs[:15], "apply_buttons": buttons, "emails_in_text": emails, "text_chars": body_len}


def run():
    results = []
    for source, label, url, pattern, kind in TESTS:
        rec = {"source": source, "label": label, "url": url, "kind": kind}
        note, rp = robots_for(url)
        rec["robots"] = note
        allowed = True if rp is None else rp.can_fetch("*", url)
        rec["robots_allows"] = allowed
        if not allowed:
            rec["status"] = "ΔΕΝ ΑΝΟΙΧΤΗΚΕ — απαγορεύεται από robots.txt"
            results.append(rec)
            print(f"[robots] {source} {label}")
            continue
        t0 = time.time()
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            rec["http"] = r.status_code
            rec["final_url"] = r.url[:200]
            rec["bytes"] = len(r.content)
            rec["seconds"] = round(time.time() - t0, 1)
            html = r.text
            soup = BeautifulSoup(html, "html.parser")
            rec["title"] = page_title(soup)
            rec["block_signs"] = block_signs(html)
            if pattern:
                ids, samples = listing_links(html, soup, pattern, r.url)
                rec["ids_in_html"] = len(ids)
                rec["ids_sample"] = sorted(ids)[:8]
                rec["anchors_with_title"] = len(samples)
                rec["samples"] = samples[:8]
            if kind == "discover":
                rec["discover"] = discover(soup, html)
            if kind == "detail":
                rec["apply"] = apply_info(soup, html, r.url)
            if kind == "api":
                rec["content_type"] = r.headers.get("content-type", "")
                rec["body_head"] = html[:400]
        except Exception as e:  # noqa: BLE001
            rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        results.append(rec)
        print(f"[{rec.get('http', 'ERR')}] {source} {label} ids={rec.get('ids_in_html')}")
        time.sleep(PAUSE)
    return results


def verdict(rec) -> str:
    if not rec.get("robots_allows", True):
        return "ΑΠΑΓΟΡΕΥΕΤΑΙ (robots.txt)"
    if "error" in rec:
        return "ΣΦΑΛΜΑ ΣΥΝΔΕΣΗΣ"
    code = rec.get("http")
    if code in (401, 403, 429, 503) or (rec.get("block_signs") and not rec.get("ids_in_html")):
        return "ΜΠΛΟΚΑΡΕΤΑΙ"
    if code and code >= 400:
        return f"HTTP {code}"
    if rec["kind"] == "detail":
        a = rec.get("apply", {})
        return "OK" if a.get("text_chars", 0) > 500 else "ΚΕΝΗ ΣΕΛΙΔΑ"
    if rec["kind"] in ("list", "discover", "api"):
        n = rec.get("ids_in_html", 0)
        return f"OK ({n} αγγελίες)" if n else "ΚΑΜΙΑ ΑΓΓΕΛΙΑ ΣΤΟ HTML"
    return "OK"


def write_report(results):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = Path("results")
    out.mkdir(exist_ok=True)
    (out / "probe-latest.json").write_text(json.dumps({"run": now, "results": results}, ensure_ascii=False, indent=1))

    lines = [f"# Δοκιμή πηγών — {now}", "", "| Πηγή | Δοκιμή | Αποτέλεσμα | HTTP | Μέγεθος | Τίτλος σελίδας |", "|---|---|---|---|---|---|"]
    for r in results:
        lines.append(
            f"| {r['source']} | {r['label']} | {verdict(r)} | {r.get('http', '')} | {r.get('bytes', '')} | {r.get('title', '')[:70]} |"
        )
    lines += ["", "## Λεπτομέρειες", ""]
    for r in results:
        lines.append(f"### {r['source']} — {r['label']}")
        lines.append(f"- URL: {r['url']}")
        if r.get("final_url") and r["final_url"] != r["url"]:
            lines.append(f"- Τελικό URL: {r['final_url']}")
        lines.append(f"- {r['robots']} · επιτρέπεται: {r['robots_allows']}")
        for k in ("http", "seconds", "block_signs", "ids_in_html", "anchors_with_title", "error", "content_type"):
            if k in r and r[k] not in (None, [], ""):
                lines.append(f"- {k}: {r[k]}")
        if r.get("samples"):
            lines.append("- Δείγμα:")
            for s in r["samples"]:
                lines.append(f"  - {s['title']} — {s['url']}")
        elif r.get("ids_sample"):
            lines.append(f"- Δείγμα id: {r['ids_sample']}")
        if r.get("apply"):
            a = r["apply"]
            lines.append(f"- Κείμενο σελίδας: {a['text_chars']} χαρακτήρες")
            lines.append(f"- Κουμπιά αίτησης: {a['apply_buttons']}")
            lines.append(f"- Emails στο κείμενο: {a['emails_in_text']}")
            for l in a["apply_links"]:
                lines.append(f"  - σύνδεσμος: «{l['text']}» → {l['href']}")
        if r.get("discover"):
            d = r["discover"]
            lines.append(f"- __NEXT_DATA__: {d['__NEXT_DATA__']}")
            for f in d["forms"]:
                lines.append(f"  - φόρμα: action={f['action']} method={f['method']} inputs={f['inputs']}")
            if d["api_strings"]:
                lines.append(f"  - API strings: {d['api_strings']}")
            if d["search_links"]:
                lines.append(f"  - σύνδεσμοι αναζήτησης: {d['search_links'][:15]}")
            if d["scripts"]:
                lines.append(f"  - scripts: {d['scripts'][:12]}")
        if r.get("body_head"):
            lines.append(f"- Αρχή απάντησης: `{r['body_head'][:300]}`")
        lines.append("")
    (out / "probe-latest.md").write_text("\n".join(lines))


if __name__ == "__main__":
    res = run()
    write_report(res)
    print("ok", len(res))
    sys.exit(0)
