"""
Phishing URL Detector
A beginner-friendly tool that checks a URL for common phishing red flags.
For educational purposes only.
"""

from urllib.parse import urlparse   # splits a URL into parts
import ipaddress                     # checks if text is an IP address
from difflib import SequenceMatcher  # measures how similar two words are

# Words phishing links often contain
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update",
                       "banking", "confirm", "password", "signin", "wallet"]

# Real brands that scammers like to imitate
POPULAR_BRANDS = ["google", "facebook", "paypal", "amazon", "apple",
                  "microsoft", "netflix", "instagram", "hdfcbank", "sbi"]


def get_hostname(url):
    """Return the domain part of a URL, e.g. 'login.paypal.com'."""
    if "://" not in url:          # user typed "paypal.com" without http://
        url = "http://" + url     # add it so urlparse works properly
    return urlparse(url).hostname or ""


def is_ip_address(hostname):
    """True if the hostname is a raw IP address like 192.168.4.5."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def count_subdomains(hostname):
    """'a.b.paypal.com' -> 2 subdomains (a and b)."""
    parts = hostname.split(".")
    return max(len(parts) - 2, 0)


def find_keywords(url):
    """Return a list of suspicious words found in the URL."""
    url_lower = url.lower()
    return [word for word in SUSPICIOUS_KEYWORDS if word in url_lower]


def normalize(text):
    """Undo look-alike tricks: paypa1 -> paypal, g00gle -> google."""
    swaps = {"0": "o", "1": "l", "3": "e", "5": "s", "4": "a"}
    for digit, letter in swaps.items():
        text = text.replace(digit, letter)
    return text


def check_lookalike(hostname):
    """Return a message if the domain imitates a popular brand, else None."""
    parts = hostname.split(".")
    if len(parts) < 2:
        return None
    main_name = parts[-2]                 # 'paypal' from 'login.paypal.com'

    if main_name in POPULAR_BRANDS:       # genuine brand domain, no flag
        return None

    clean_name = normalize(main_name)
    clean_host = normalize(hostname)

    for brand in POPULAR_BRANDS:
        similarity = SequenceMatcher(None, clean_name, brand).ratio()
        if similarity >= 0.8:
            return f"Domain '{main_name}' looks like '{brand}'"
        if brand in clean_host:
            return f"Brand '{brand}' appears inside an unrelated domain"
    return None


def analyze_url(url):
    """Run all checks. Returns (score, list_of_reasons)."""
    score = 0
    reasons = []
    hostname = get_hostname(url)
    using_ip = is_ip_address(hostname)

    if using_ip:
        score += 3
        reasons.append("Uses an IP address instead of a domain name")

    subs = count_subdomains(hostname)
    if subs >= 3:
        score += 2
        reasons.append(f"Too many subdomains ({subs})")

    found = find_keywords(url)
    if found:
        score += len(found)               # +1 per suspicious word
        reasons.append(f"Suspicious keywords: {', '.join(found)}")

    if not using_ip:
        lookalike = check_lookalike(hostname)
        if lookalike:
            score += 3
            reasons.append(lookalike)

    if "@" in url:
        score += 2
        reasons.append("Contains '@' (can hide the real destination)")

    if len(url) > 75:
        score += 1
        reasons.append("Very long URL")

    if hostname.count("-") >= 2:
        score += 1
        reasons.append("Many hyphens in the domain")

    if not url.lower().startswith("https://"):
        score += 1
        reasons.append("Does not use HTTPS")

    return score, reasons


def get_verdict(score):
    """Turn a score into a human-readable verdict."""
    if score >= 5:
        return "LIKELY PHISHING"
    elif score >= 3:
        return "SUSPICIOUS"
    return "LOOKS SAFE"


def main():
    print("=== Phishing URL Detector ===")
    print("Type a URL to check it, or 'quit' to exit.\n")
    while True:                           # repeat until the user quits
        url = input("Enter URL: ").strip()
        if url.lower() == "quit":
            break
        if not url:
            continue                      # skip empty input
        score, reasons = analyze_url(url)
        print(f"\nScore: {score}  ->  {get_verdict(score)}")
        for reason in reasons:
            print(f"  - {reason}")
        print()


if __name__ == "__main__":
    main()