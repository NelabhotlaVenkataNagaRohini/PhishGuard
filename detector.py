import re
from urllib.parse import urlparse


# Common URL-shortening services
SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly"
]


# Words commonly seen in suspicious URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "password",
    "bank",
    "secure",
    "confirm",
    "payment",
    "wallet"
]


def analyze_url(url):

    risk_score = 0
    reasons = []

    features = {
        "https": False,
        "ip_address": False,
        "long_url": False,
        "url_shortener": False,
        "suspicious_keywords": False,
        "punycode": False,
        "multiple_subdomains": False
    }

    # ------------------------------------------------
    # 1. Basic input validation
    # ------------------------------------------------

    url = url.strip()

    if not url:
        return {
            "score": 0,
            "result": "Invalid URL",
            "reasons": ["No URL was provided"]
        }

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Remove port number if present
    domain_without_port = domain.split(":")[0]


    # ------------------------------------------------
    # 2. HTTPS check
    # ------------------------------------------------

    if parsed.scheme != "https":
    	risk_score += 15
    	reasons.append("URL does not use HTTPS")
    else:
    	features["https"] = True
    	reasons.append("HTTPS is enabled")


    # ------------------------------------------------
    # 3. IP address check
    # ------------------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain_without_port):
    	risk_score += 25
    	features["ip_address"] = True
    	reasons.append(
        	"URL uses an IP address instead of a domain name"
    	)


    # ------------------------------------------------
    # 4. URL length check
    # ------------------------------------------------

    if len(url) > 100:
    	risk_score += 10
    	features["long_url"] = True
    	reasons.append("URL is unusually long")


    # ------------------------------------------------
    # 5. @ symbol check
    # ------------------------------------------------

    if "@" in url:
        risk_score += 20
        reasons.append("URL contains an @ symbol")


    # ------------------------------------------------
    # 6. Suspicious keywords
    # ------------------------------------------------

    found_words = []

    for word in SUSPICIOUS_KEYWORDS:

        if word in url.lower():
            found_words.append(word)

    if found_words:

    	risk_score += 10
    	features["suspicious_keywords"] = True

    	reasons.append(
        	"Contains security-sensitive keywords: "
        	+ ", ".join(found_words)
    	)


    # ------------------------------------------------
    # 7. URL shortening service
    # ------------------------------------------------

    if domain_without_port in SHORTENING_SERVICES:

    	risk_score += 20
    	features["url_shortener"] = True

    	reasons.append(
        	"URL uses a known URL-shortening service"
    	)


    # ------------------------------------------------
    # 8. Multiple subdomains
    # ------------------------------------------------

    domain_parts = domain_without_port.split(".")

    if len(domain_parts) > 3:

    	risk_score += 10
    	features["multiple_subdomains"] = True

    	reasons.append(
        	"Domain contains multiple subdomains"
    	)


    # ------------------------------------------------
    # 9. Suspicious characters
    # ------------------------------------------------

    special_characters = ["-", "_"]

    special_count = sum(
        url.count(character)
        for character in special_characters
    )

    if special_count >= 4:

        risk_score += 10

        reasons.append(
            "URL contains an unusually high number of "
            "special characters"
        )


    # ------------------------------------------------
    # 10. Punycode / IDN check
    # ------------------------------------------------

    if "xn--" in domain_without_port:

    	risk_score += 20
    	features["punycode"] = True

    	reasons.append(
        	"Domain uses Punycode, which can sometimes "
        	"be used in look-alike domains"
    	)


    # ------------------------------------------------
    # 11. Suspicious path
    # ------------------------------------------------

    suspicious_path_words = [
        "login",
        "verify",
        "password",
        "credential",
        "signin"
    ]

    found_path_words = []

    for word in suspicious_path_words:

        if word in path:
            found_path_words.append(word)

    if found_path_words:

        risk_score += 5

        reasons.append(
            "URL path contains sensitive keywords: "
            + ", ".join(found_path_words)
        )


    # ------------------------------------------------
    # Limit score
    # ------------------------------------------------

    risk_score = min(risk_score, 100)


    # ------------------------------------------------
    # Determine risk category
    # ------------------------------------------------

    if risk_score >= 50:
    	result = "High Risk"

    elif risk_score >= 20:
    	result = "Suspicious"

    else:
    	result = "Likely Safe"


    return {
    	"score": risk_score,
    	"result": result,
    	"reasons": reasons,
    	"features": features
    }