#!/usr/bin/env python3
"""SiteSentinel: minimal official security-advisory email monitor."""
import json
import os
import re
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET

STATE_FILE = Path("state/seen.json")
WINDOW_DAYS = 14
FEEDS = {
    "PHP": "https://www.php.net/feed.atom",
    "WordPress": "https://wordpress.org/news/category/security/feed/",
}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Customize these terms after we inventory actual site technologies.
KEV_PRODUCTS = ("php", "wordpress")
TRIGGERS = ("security", "vulnerab", "critical", "remote code", "exploit", "patch")
USER_AGENT = "SiteSentinel/0.1 (+https://github.com/ArianaRam/SiteSentinel)"


def fetch(url):
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=25) as response:
        return response.read()


def clean(value):
    return re.sub(r"<[^>]*>", " ", unescape(value or "")).strip()


def date_or_none(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        try:
            return parsedate_to_datetime(value).astimezone(timezone.utc)
        except (ValueError, TypeError):
            return None


def feed_items(source, data):
    root = ET.fromstring(data)
    items = []
    for entry in root.findall(".//{http://www.w3.org/2005/Atom}entry"):
        def atom(name):
            return entry.findtext("{http://www.w3.org/2005/Atom}" + name, default="")
        links = entry.findall("{http://www.w3.org/2005/Atom}link")
        link = next((x.get("href", "") for x in links if x.get("rel", "alternate") == "alternate"), "")
        items.append((atom("title"), atom("summary") or atom("content"), link, atom("published") or atom("updated")))
    for entry in root.findall(".//item"):
        def rss(name):
            return entry.findtext(name, default="")
        items.append((rss("title"), rss("description"), rss("link"), rss("pubDate")))
    result = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    for title, body, link, published in items:
        date = date_or_none(published)
        combined = (title + " " + clean(body)).lower()
        if not date or date < cutoff or not any(word in combined for word in TRIGGERS):
            continue
        # Only notify on PHP advisories/security releases, not ordinary feature releases.
        if source == "PHP" and not any(word in combined for word in ("security", "vulnerab", "critical", "remote code")):
            continue
        result.append({"id": source + ":" + link, "source": source, "title": clean(title),
                       "url": link, "date": date.date().isoformat()})
    return result


def kev_items(data):
    catalog = json.loads(data)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)).date()
    result = []
    for entry in catalog.get("vulnerabilities", []):
        product = " ".join((entry.get("vendorProject", ""), entry.get("product", ""))).lower()
        date = date_or_none(entry.get("dateAdded"))
        # dateAdded is normally YYYY-MM-DD.
        if date is None:
            try:
                date = datetime.strptime(entry["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except (KeyError, ValueError):
                continue
        if date.date() < cutoff or not any(term in product for term in KEV_PRODUCTS):
            continue
        cve = entry.get("cveID", "")
        result.append({"id": "CISA:" + cve, "source": "CISA KEV",
                       "title": cve + " — " + entry.get("vulnerabilityName", "Known exploited vulnerability"),
                       "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                       "date": date.date().isoformat()})
    return result


def collect():
    findings, errors = [], []
    for source, url in FEEDS.items():
        try:
            findings.extend(feed_items(source, fetch(url)))
        except Exception as exc:
            errors.append(f"{source}: {type(exc).__name__}: {exc}")
    try:
        findings.extend(kev_items(fetch(KEV_URL)))
    except Exception as exc:
        errors.append(f"CISA KEV: {type(exc).__name__}: {exc}")
    return findings, errors


def send_mail(findings, errors):
    recipients = [x.strip() for x in os.environ["ALERT_TO"].split(",") if x.strip()]
    if not recipients:
        raise RuntimeError("ALERT_TO contains no recipients")
    mail = EmailMessage()
    mail["Subject"] = f"[SiteSentinel] {len(findings)} new advisory(s)" if findings else "[SiteSentinel] Feed check failed"
    mail["From"] = os.environ["ALERT_FROM"]
    mail["To"] = ", ".join(recipients)
    lines = ["Potentially relevant security notices (exposure NOT verified):", ""]
    for item in findings:
        lines.extend([f"[{item['source']}] {item['title']}", f"Published: {item['date']}",
                      item["url"], ""])
    if errors:
        lines.extend(["Feed errors requiring investigation:", *errors, ""])
    lines.append("Please verify your affected software versions and apply vendor patches.")
    mail.set_content("\n".join(lines))
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=25, context=context) as smtp:
            smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(mail)
    else:
        with smtplib.SMTP(host, port, timeout=25) as smtp:
            smtp.starttls(context=context)
            smtp.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
            smtp.send_message(mail)


def main():
    findings, errors = collect()
    if len(errors) == len(FEEDS) + 1:
        raise RuntimeError("All security feeds failed: " + "; ".join(errors))
    required = ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "ALERT_FROM", "ALERT_TO")
    if any(not os.environ.get(key) for key in required):
        print("Email secrets not configured; no email sent and no advisories marked as seen.")
        print(f"Found {len(findings)} recent advisory entries; {len(errors)} feed errors.")
        return
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"seen": []}
    seen = set(state.get("seen", []))
    new = [item for item in findings if item["id"] not in seen]
    # Never silently swallow source failure. Alert and retry failed feeds tomorrow.
    if new or errors:
        send_mail(new, errors)
        print(f"Sent alert: {len(new)} new notices; {len(errors)} feed errors.")
    else:
        print("No new notices.")
    seen.update(item["id"] for item in new)
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"seen": sorted(seen)}, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"SiteSentinel failed: {error}", file=sys.stderr)
        sys.exit(1)
