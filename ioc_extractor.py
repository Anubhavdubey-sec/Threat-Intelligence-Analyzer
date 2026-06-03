import re
from urllib.parse import urlparse


def extract_iocs(text):

    ips = list(set(
        re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            text
        )
    ))

    urls = list(set(
        re.findall(
            r'https?://[^\s]+',
            text
        )
    ))

    emails = list(set(
        re.findall(
            r'[\w\.-]+@[\w\.-]+\.\w+',
            text
        )
    ))

    hashes = list(set(
        re.findall(
            r'\b[a-fA-F0-9]{64}\b',
            text
        )
    ))

    domains = []

    for url in urls:
        try:
            domains.append(urlparse(url).netloc)
        except:
            pass

    domains = list(set(domains))

    return {
        "ips": ips,
        "urls": urls,
        "emails": emails,
        "hashes": hashes,
        "domains": domains
    }


def calculate_risk(iocs):

    score = 0

    score += len(iocs["ips"]) * 10
    score += len(iocs["domains"]) * 15
    score += len(iocs["urls"]) * 20
    score += len(iocs["emails"]) * 10
    score += len(iocs["hashes"]) * 25

    if score >= 70:
        severity = "HIGH"

    elif score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return score, severity