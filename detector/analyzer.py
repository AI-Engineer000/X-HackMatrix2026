import re
from urllib.parse import urlparse


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):
    """
    Performs deeper analysis of a single URL.
    Returns a score contribution and additional signals.
    """

    url_score = 0
    url_signals = []

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    domain = parsed.netloc.lower()

    # Remove username/password portion
    if "@" in domain:
        domain = domain.split("@")[-1]

    # Remove port
    if ":" in domain:
        domain = domain.split(":")[0]

    # --------------------------------------------------------
    # 1. HTTP
    # --------------------------------------------------------

    if url.lower().startswith("http://"):

        url_score += 5

        url_signals.append({
            "category": "Insecure Link",
            "description": (
                "The link uses HTTP instead of HTTPS."
            ),
            "evidence": "http://"
        })

    # --------------------------------------------------------
    # 2. SHORTENED URL
    # --------------------------------------------------------

    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at"
    }

    if domain in shorteners:

        url_score += 15

        url_signals.append({
            "category": "Shortened URL",
            "description": (
                "The link uses a URL-shortening service "
                "that hides the final destination."
            ),
            "evidence": domain
        })

    # --------------------------------------------------------
    # 3. IP-BASED URL
    # --------------------------------------------------------

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain):

        url_score += 20

        url_signals.append({
            "category": "IP-Based URL",
            "description": (
                "The link uses an IP address instead of "
                "a normal domain name."
            ),
            "evidence": domain
        })

    # --------------------------------------------------------
    # 4. @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        url_score += 20

        url_signals.append({
            "category": "Suspicious URL Structure",
            "description": (
                "The URL contains an '@' symbol, which can "
                "obscure the actual destination."
            ),
            "evidence": "@"
        })

    # --------------------------------------------------------
    # 5. COMPLEX DOMAIN
    # --------------------------------------------------------

    domain_parts = [
        part
        for part in domain.split(".")
        if part
    ]

    if len(domain_parts) >= 4:

        url_score += 10

        url_signals.append({
            "category": "Complex Domain",
            "description": (
                "The URL contains an unusually large "
                "number of domain levels."
            ),
            "evidence": domain
        })

    return {
        "url_score": min(url_score, 50),
        "url_signals": url_signals
    }


# ============================================================
# MESSAGE ANALYSIS
# ============================================================

def analyze_message(message):

    text = message.lower().strip()

    risk_score = 0
    signals = []
    detected_categories = set()

    # --------------------------------------------------------
    # Helper: Add Signal
    # --------------------------------------------------------

    def add_signal(category, description, evidence, score):

        nonlocal risk_score

        # Prevent duplicate category signals
        if category in detected_categories:
            return

        risk_score += score

        signals.append({
            "category": category,
            "description": description,
            "evidence": evidence
        })

        detected_categories.add(category)

    # ========================================================
    # 1. URGENCY / PRESSURE
    # ========================================================

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "limited time",
        "within 24 hours",
        "hurry",
        "do it now",
        "last chance"
    ]

    detected_urgency = next(
        (word for word in urgency_words if word in text),
        None
    )

    if detected_urgency:

        add_signal(
            "Urgency",
            "Urgent or pressure-based language detected.",
            detected_urgency,
            15
        )

    # ========================================================
    # 2. FINANCIAL / SENSITIVE INFORMATION
    # ========================================================

    financial_words = [
        "payment",
        "pay",
        "bank",
        "upi",
        "account",
        "otp",
        "credit card",
        "debit card",
        "password",
        "pin",
        "cvv"
    ]

    detected_financial = [
        word
        for word in financial_words
        if word in text
    ]

    if detected_financial:

        add_signal(
            "Sensitive Information",
            "Financial or sensitive information is mentioned.",
            ", ".join(detected_financial[:3]),
            15
        )

    # ========================================================
    # 3. REWARD / PRIZE
    # ========================================================

    reward_words = [
        "won",
        "winner",
        "prize",
        "lottery",
        "reward",
        "cashback",
        "free gift",
        "lucky winner"
    ]

    detected_reward = next(
        (word for word in reward_words if word in text),
        None
    )

    if detected_reward:

        add_signal(
            "Reward / Prize",
            "Unexpected reward or prize language detected.",
            detected_reward,
            15
        )

    # ========================================================
    # 4. THREAT / CONSEQUENCE
    # ========================================================

    threat_words = [
        "account will be blocked",
        "account will be suspended",
        "legal action",
        "police complaint",
        "your account will be closed",
        "service will be terminated",
        "verification failed"
    ]

    detected_threat = next(
        (word for word in threat_words if word in text),
        None
    )

    if detected_threat:

        add_signal(
            "Threat",
            "Threatening or consequence-based language detected.",
            detected_threat,
            20
        )

    # ========================================================
    # 5. KYC / VERIFICATION
    # ========================================================

    verification_words = [
        "verify your account",
        "verify kyc",
        "kyc update",
        "complete kyc",
        "update kyc",
        "verify now",
        "identity verification"
    ]

    detected_verification = next(
        (word for word in verification_words if word in text),
        None
    )

    if detected_verification:

        add_signal(
            "Verification Request",
            "The message asks for account or identity verification.",
            detected_verification,
            15
        )

    # ========================================================
    # 6. URL DETECTION
    # ========================================================

    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text
    )

    if urls:

        url = urls[0].rstrip(".,!?;:")

        # ----------------------------------------------------
        # External Link
        # ----------------------------------------------------

        add_signal(
            "External Link",
            "An external link was found in the message.",
            url,
            10
        )

        # ----------------------------------------------------
        # Deep URL Analysis
        # ----------------------------------------------------

        url_result = analyze_url(url)

        for url_signal in url_result["url_signals"]:

            category = url_signal["category"]

            # Don't duplicate an existing category
            if category not in detected_categories:

                signals.append(url_signal)
                detected_categories.add(category)

                risk_score += (
                    {
                        "Insecure Link": 5,
                        "Shortened URL": 15,
                        "IP-Based URL": 20,
                        "Suspicious URL Structure": 20,
                        "Complex Domain": 10
                    }.get(category, 0)
                )

        # ----------------------------------------------------
        # Suspicious Domain Words
        # ----------------------------------------------------

        suspicious_domain_words = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "payment",
            "kyc",
            "bank"
        ]

        url_lower = url.lower()

        suspicious_words_found = [
            word
            for word in suspicious_domain_words
            if word in url_lower
        ]

        if suspicious_words_found:

            add_signal(
                "Suspicious URL Pattern",
                (
                    "The URL contains words commonly associated "
                    "with account verification or financial activity."
                ),
                ", ".join(suspicious_words_found[:3]),
                10
            )

        # ----------------------------------------------------
        # Brand Impersonation
        # ----------------------------------------------------

        parsed = urlparse(
            url if "://" in url else "http://" + url
        )

        domain_name = parsed.netloc.lower()

        if "@" in domain_name:
            domain_name = domain_name.split("@")[-1]

        if ":" in domain_name:
            domain_name = domain_name.split(":")[0]

        brands = [
            "paypal",
            "paytm",
            "sbi",
            "amazon",
            "google",
            "microsoft",
            "apple",
            "instagram",
            "facebook",
            "netflix"
        ]

        for brand in brands:

            if brand in domain_name:

                legitimate_domains = {
                    f"{brand}.com",
                    f"www.{brand}.com",
                    f"{brand}.in",
                    f"www.{brand}.in"
                }

                if domain_name not in legitimate_domains:

                    add_signal(
                        "Possible Brand Impersonation",
                        (
                            f"The URL contains '{brand}' "
                            "but does not match a recognised "
                            "simple domain."
                        ),
                        domain_name,
                        15
                    )

                break

    # ========================================================
    # 7. SENSITIVE DATA REQUEST
    # ========================================================

    sensitive_patterns = [
        r"share.*otp",
        r"send.*otp",
        r"enter.*otp",
        r"share.*pin",
        r"share.*password",
        r"provide.*cvv",
        r"send.*bank details"
    ]

    sensitive_request = any(
        re.search(pattern, text)
        for pattern in sensitive_patterns
    )

    if sensitive_request:

        add_signal(
            "Sensitive Data Request",
            (
                "The message appears to request "
                "confidential information."
            ),
            "OTP / PIN / password / banking details",
            25
        )

    # ========================================================
    # 8. AUTHORITY / BRAND REFERENCE
    # ========================================================

    authority_words = [
        "bank",
        "bank security",
        "customer support",
        "support team",
        "security team",
        "official team",
        "government",
        "police",
        "income tax",
        "rbi",
        "sbi",
        "paytm",
        "amazon",
        "google",
        "microsoft",
        "paypal"
    ]

    detected_authority = [
        word
        for word in authority_words
        if word in text
    ]

    if detected_authority:

        add_signal(
            "Authority / Brand Reference",
            (
                "The message refers to a financial institution, "
                "company, government body, or support authority."
            ),
            ", ".join(detected_authority[:3]),
            5
        )

    # ========================================================
    # 9. PAYMENT PRESSURE
    # ========================================================

    payment_pressure_patterns = [
        "pay immediately",
        "make payment now",
        "payment required",
        "pay to avoid",
        "pay now",
        "send money",
        "transfer money",
        "complete payment",
        "payment pending"
    ]

    detected_payment_pressure = [
        pattern
        for pattern in payment_pressure_patterns
        if pattern in text
    ]

    if detected_payment_pressure:

        add_signal(
            "Payment Pressure",
            (
                "The message creates pressure to make "
                "a payment or transfer money."
            ),
            detected_payment_pressure[0],
            15
        )

    # ========================================================
    # 10. ACCOUNT ACCESS PRESSURE
    # ========================================================

    access_patterns = [
        "verify your account",
        "confirm your identity",
        "verify your identity",
        "login immediately",
        "sign in now",
        "update your account",
        "unlock your account",
        "restore your account"
    ]

    detected_access = [
        pattern
        for pattern in access_patterns
        if pattern in text
    ]

    if detected_access:

        add_signal(
            "Account Access Pressure",
            (
                "The message attempts to make the recipient "
                "verify, access, unlock, or update an account."
            ),
            detected_access[0],
            10
        )

    # ========================================================
    # 11. CONTEXTUAL / COMBINATION RISK
    # ========================================================

    categories = set(
        signal["category"]
        for signal in signals
    )

    # --------------------------------------------------------
    # Reward + Urgency
    # --------------------------------------------------------

    if (
        "Reward / Prize" in categories
        and "Urgency" in categories
    ):

        risk_score += 10

        signals.append({
            "category": "Social Engineering Pattern",
            "description": (
                "The message combines an unexpected reward "
                "with pressure to act quickly."
            ),
            "evidence": "Reward + Urgency"
        })

    # --------------------------------------------------------
    # Sensitive Information + Data Request
    # --------------------------------------------------------

    if (
        "Sensitive Information" in categories
        and "Sensitive Data Request" in categories
    ):

        risk_score += 15

        signals.append({
            "category": "Sensitive Data Risk",
            "description": (
                "The message mentions financial information "
                "and also requests confidential data."
            ),
            "evidence": "Financial information + Data request"
        })

    # --------------------------------------------------------
    # Threat + Verification
    # --------------------------------------------------------

    if (
        "Threat" in categories
        and "Verification Request" in categories
    ):

        risk_score += 10

        signals.append({
            "category": "Account Threat Pattern",
            "description": (
                "The message uses a threat or consequence "
                "to pressure the recipient into verification."
            ),
            "evidence": "Threat + Verification"
        })

    # --------------------------------------------------------
    # Urgency + Suspicious URL
    # --------------------------------------------------------

    suspicious_url_categories = {
        "Shortened URL",
        "IP-Based URL",
        "Possible Brand Impersonation",
        "Suspicious URL Pattern"
    }

    if (
        "Urgency" in categories
        and categories.intersection(suspicious_url_categories)
    ):

        risk_score += 10

        signals.append({
            "category": "Urgent Link Pattern",
            "description": (
                "The message combines urgent language "
                "with a suspicious link."
            ),
            "evidence": "Urgency + Suspicious URL"
        })

    # --------------------------------------------------------
    # Authority + Threat + Verification
    # --------------------------------------------------------

    if (
        "Authority / Brand Reference" in categories
        and "Threat" in categories
        and "Verification Request" in categories
    ):

        risk_score += 15

        signals.append({
            "category": "Authority Impersonation Pattern",
            "description": (
                "The message references an authority or brand "
                "while using threats and verification pressure."
            ),
            "evidence": "Authority + Threat + Verification"
        })

    # --------------------------------------------------------
    # Authority + Link + Urgency
    # --------------------------------------------------------

    if (
        "Authority / Brand Reference" in categories
        and "External Link" in categories
        and "Urgency" in categories
    ):

        risk_score += 10

        signals.append({
            "category": "Social Engineering Pattern",
            "description": (
                "The message combines authority references, "
                "urgency, and an external link."
            ),
            "evidence": "Authority + Urgency + Link"
        })

    # --------------------------------------------------------
    # Payment + Urgency
    # --------------------------------------------------------

    if (
        "Payment Pressure" in categories
        and "Urgency" in categories
    ):

        risk_score += 10

        signals.append({
            "category": "Payment Scam Pattern",
            "description": (
                "The message pressures the recipient "
                "to make a payment quickly."
            ),
            "evidence": "Payment + Urgency"
        })

    # ========================================================
    # 12. FINAL SCORE
    # ========================================================

    risk_score = min(max(risk_score, 0), 100)

    # ========================================================
    # 13. RISK LEVEL
    # ========================================================

    if risk_score >= 60:

        risk_level = "HIGH RISK"

    elif risk_score >= 30:

        risk_level = "MEDIUM RISK"

    else:

        risk_level = "LOW RISK"

    # ========================================================
    # 14. RECOMMENDATION
    # ========================================================

    if risk_level == "HIGH RISK":

        recommendation = (
            "Do not click suspicious links or share "
            "OTP, passwords, PINs, or banking information."
        )

    elif risk_level == "MEDIUM RISK":

        recommendation = (
            "Be cautious. Verify the sender and information "
            "through an official source before taking action."
        )

    else:

        recommendation = (
            "No major scam indicators were detected. "
            "Still verify unexpected messages before acting."
        )

    # ========================================================
    # 15. FINAL RESULT
    # ========================================================

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signals": signals,
        "recommendation": recommendation
    }
