from .whois import whois_lookup


def whois(domain: str):
    return whois_lookup(domain)
