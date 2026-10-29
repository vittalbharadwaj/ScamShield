"""Deterministic first-pass checks. No network, no model: just patterns that
are cheap to verify and hard to argue with (lookalike domains, shorteners,
UPI IDs, phone numbers). The LLM gets these as extra evidence."""
import re
from urllib.parse import urlparse

URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\"']+"
    r"|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|co\.in|net|org|xyz|top|click|link|info|online|site|live|shop|cc|vip|icu|buzz|app|cyou|sbs)(?:/[^\s<>\"']*)?"
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
UPI_RE = re.compile(
    r"(?i)\b[\w.\-]{2,}@(?:ok\w+|ybl|ibl|axl|paytm|upi|apl|sbi|hdfcbank|icici|axisbank|pingpay|freecharge)\b"
)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "goo.gl",
              "shorturl.at", "rebrand.ly", "tiny.cc", "ow.ly", "bitly.com"}
RISKY_TLDS = {"xyz", "top", "click", "icu", "buzz", "vip", "cc", "live", "shop",
              "online", "site", "link", "cyou", "sbs", "rest"}
TWO_PART_SUFFIXES = {"co.in", "org.in", "gov.in", "nic.in", "ac.in", "net.in", "co.uk"}

OFFICIAL = {
    "sbi": {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi", "sbicard.com", "sbilife.co.in", "sbimf.com", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcsec.com"},
    "icici": {"icicibank.com", "icicisecurities.com", "iciciprulife.com", "icicidirect.com"},
    "axis": {"axisbank.com", "axis.bank.in"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "amazon": {"amazon.in", "amazon.com", "amzn.in", "amzn.to"},
    "flipkart": {"flipkart.com", "fkrt.it"},
    "irctc": {"irctc.co.in", "irctc.com"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "epfo": {"epfindia.gov.in", "epfindia.com"},
    "uidai": {"uidai.gov.in"},
}

URGENCY_RE = re.compile(
    r"(?i)\b(immediately|urgent(ly)?|within \d+ ?(hours?|hrs?|minutes?|mins?)|blocked|suspended|"
    r"last warning|expires?|expired|today only|act now|limited seats)\b")
SECRETS_RE = re.compile(r"(?i)\b(otp|pin|cvv|password|aadhaar|aadhar|pan card|card number)\b")
MONEY_RE = re.compile(
    r"(?i)\b(processing fee|registration fee|advance|refund|lottery|prize|winner|lucky draw|"
    r"kyc|anydesk|teamviewer|\.apk|customs|guaranteed returns?|double your)\b")


def root_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def host_of(url: str) -> str:
    u = url if re.match(r"(?i)https?://", url) else "http://" + url
    return (urlparse(u).hostname or "").lower()


def extract_entities(text: str) -> dict:
    urls = [u.rstrip(".,);]'\"") for u in URL_RE.findall(text)]
    phones = []
    for p in PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", p)[-10:]
        if digits not in phones:
            phones.append(digits)
    upis = list(dict.fromkeys(UPI_RE.findall(text)))
    return {"urls": list(dict.fromkeys(urls)), "phones": phones, "upi_ids": upis}


def scan(text: str) -> dict:
    ents = extract_entities(text)
    signals: list[str] = []
    floor = 0

    for url in ents["urls"]:
        host = host_of(url)
        if not host:
            continue
        root = root_domain(host)
        tld = host.rsplit(".", 1)[-1]
        if root in SHORTENERS:
            signals.append(f"Link uses a URL shortener ({host}), which hides the real destination")
        if tld in RISKY_TLDS:
            signals.append(f"Link domain ends in .{tld}, a TLD often used for throwaway scam sites")
        if host.endswith(".gov.in") or host.endswith(".nic.in"):
            continue
        for brand, official in OFFICIAL.items():
            if brand in host.replace("-", "") and root not in official:
                signals.append(f"'{host}' mentions {brand.upper()} but is not a known {brand.upper()} domain")
                floor = max(floor, 65)

    if ents["upi_ids"]:
        signals.append("Message asks for payment to a personal UPI ID: " + ", ".join(ents["upi_ids"]))
    if URGENCY_RE.search(text):
        signals.append("Uses urgency or threat language to rush the reader")
    if SECRETS_RE.search(text):
        signals.append("Mentions OTP, PIN, password or ID numbers (genuine senders never ask you to share these)")
    if MONEY_RE.search(text):
        signals.append("Contains a classic scam hook (fee, prize, KYC, refund or remote-access app)")

    return {"entities": ents, "signals": signals, "floor": floor}
