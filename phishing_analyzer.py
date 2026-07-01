"""Phishing Scanner analysis engine.

Single source of truth for phishing detection logic. Both the Telegram bot
(bot.py) and the web app (app.py) call analyze_email() and use its output
as-is. No network calls are made here — analysis is fully local.
"""

from __future__ import annotations

import base64
import quopri
import re
import difflib
from email import message_from_string
from email.header import decode_header
from email.utils import parseaddr
from html import unescape
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"high": 25, "medium": 12, "low": 5}

VERDICT_THRESHOLDS = (
    (60, "high", "🔴", "Высокий риск"),
    (30, "medium", "🟠", "Средний риск"),
    (1, "low", "🟡", "Низкий риск"),
    (0, "safe", "🟢", "Безопасно"),
)

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "clck.ru", "vk.cc",
    "s.id", "rb.gy", "shorte.st", "adf.ly",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "link", "country", "gq", "tk",
    "ml", "cf", "ga", "loan", "win", "review", "date", "stream", "icu",
    "fit", "bid", "party", "men", "kim", "cricket", "accountant",
}

# brand keyword (found in display names / text) -> set of legitimate domains
KNOWN_BRANDS = {
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "outlook.com", "office.com", "live.com"},
    "google": {"google.com", "gmail.com"},
    "amazon": {"amazon.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ebay": {"ebay.com"},
    "сбербанк": {"sberbank.ru", "sber.ru"},
    "sberbank": {"sberbank.ru", "sber.ru"},
    "тинькофф": {"tinkoff.ru", "tbank.ru"},
    "tinkoff": {"tinkoff.ru", "tbank.ru"},
    "госуслуги": {"gosuslugi.ru"},
    "gosuslugi": {"gosuslugi.ru"},
    "альфа-банк": {"alfabank.ru"},
    "alfabank": {"alfabank.ru"},
}
ALL_BRAND_DOMAINS = {d for domains in KNOWN_BRANDS.values() for d in domains}

URGENCY_PATTERNS = [
    r"\bсроч\w*", r"\bнемедленн\w*", r"\bблокир\w*", r"\bприостановлен\w*",
    r"\bограничен\w* доступ", r"\bпоследн\w* (шанс|день|напомин\w*)",
    r"\baккаунт.{0,15}(заблок|огранич|приостановлен)",
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bexpir(e|es|ed|ing)\b",
    r"\bsuspend(ed|ing)?\b", r"\blimited time\b", r"\bverify your account\b",
    r"\bwithin 24 hours\b", r"\byour account (has been|will be) (locked|suspended|disabled)\b",
]

CREDENTIAL_PATTERNS = [
    r"\bпарол\w*", r"\bномер карты\b", r"\bcvv\b", r"\bcvc\b",
    r"\bпин-?код\w*", r"\bдан(ные|ных) карт\w*", r"\bподтверди\w* учетн\w* запис\w*",
    r"\blogin and password\b", r"\bpassword\b", r"\bcredit card number\b",
    r"\bsocial security number\b", r"\bssn\b", r"\bconfirm your (account|identity|password)\b",
    r"\bbank account (number|details)\b", r"\bwire transfer\b",
]

GENERIC_GREETING_PATTERNS = [
    r"^\s*dear (customer|user|sir|madam|sir/madam|valued customer)\b",
    r"^\s*уважаем\w* (клиент|пользователь|пользователи)\b",
    r"^\s*здравствуйте!?\s*$",
    r"^\s*hello,?\s*$",
]

# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def analyze_email(raw_input: str) -> dict:
    """Analyze raw email text (with headers) or arbitrary text.

    Returns a dict with score, verdict, flags[], links[], and metadata.
    """
    raw_input = raw_input or ""
    is_raw = _looks_like_raw_email(raw_input)

    flags = []
    headers_meta = {}

    if is_raw:
        msg = message_from_string(raw_input)
        headers_meta = _extract_header_meta(msg)
        flags.extend(_check_headers(msg, headers_meta))
        bodies = _extract_bodies(msg)
    else:
        bodies = {"plain": raw_input, "html": ""}

    combined_text = "\n".join(v for v in bodies.values() if v)
    links = _extract_links(bodies.get("plain", ""), bodies.get("html", ""))
    link_results = []
    for url in links:
        link_flags = _check_link(url, links[url])
        link_results.append({
            "url": url,
            "domain": _hostname(url),
            "flags": link_flags,
        })
        flags.extend(link_flags)

    flags.extend(_check_text(combined_text))

    score = _compute_score(flags)
    verdict, emoji, label = _verdict_for_score(score)

    return {
        "score": score,
        "verdict": verdict,
        "verdict_emoji": emoji,
        "verdict_label": label,
        "is_raw_email": is_raw,
        "flags": flags,
        "links": link_results,
        "total_links": len(link_results),
        "meta": headers_meta,
    }


# ---------------------------------------------------------------------------
# Raw email detection & parsing (FR-1, FR-2)
# ---------------------------------------------------------------------------


def _looks_like_raw_email(text: str) -> bool:
    head = text[:4000]
    has_from = re.search(r"(?im)^from:\s*\S", head) is not None
    has_subject = re.search(r"(?im)^subject:\s*\S", head) is not None
    has_to = re.search(r"(?im)^to:\s*\S", head) is not None
    return sum([has_from, has_subject, has_to]) >= 2


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        parts = decode_header(value)
        return "".join(
            part.decode(enc or "utf-8", errors="replace") if isinstance(part, bytes) else part
            for part, enc in parts
        )
    except Exception:
        return value


def _extract_header_meta(msg) -> dict:
    from_header = _decode(msg.get("From", ""))
    reply_to_header = _decode(msg.get("Reply-To", ""))
    return_path_header = _decode(msg.get("Return-Path", ""))
    from_name, from_addr = parseaddr(from_header)
    _, reply_to_addr = parseaddr(reply_to_header)
    _, return_path_addr = parseaddr(return_path_header)
    return {
        "from": from_header,
        "from_display_name": from_name,
        "from_domain": _domain_of_addr(from_addr),
        "reply_to_domain": _domain_of_addr(reply_to_addr),
        "return_path_domain": _domain_of_addr(return_path_addr),
        "subject": _decode(msg.get("Subject", "")),
    }


def _domain_of_addr(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].strip().lower().rstrip(".")


def _extract_bodies(msg) -> dict:
    bodies = {"plain": "", "html": ""}
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            if ctype == "text/plain" and not bodies["plain"]:
                bodies["plain"] = _decode_payload(part)
            elif ctype == "text/html" and not bodies["html"]:
                bodies["html"] = _decode_payload(part)
    else:
        ctype = msg.get_content_type()
        payload = _decode_payload(msg)
        if ctype == "text/html":
            bodies["html"] = payload
        else:
            bodies["plain"] = payload
    return bodies


def _decode_payload(part) -> str:
    # Messages are parsed from str (message_from_string), so get_payload(decode=True)
    # mangles non-ASCII text via raw-unicode-escape. Decode manually instead.
    payload = part.get_payload(decode=False)
    if not isinstance(payload, str):
        return ""
    cte = (part.get("Content-Transfer-Encoding", "") or "").strip().lower()
    charset = part.get_content_charset() or "utf-8"
    try:
        if cte == "base64":
            return base64.b64decode(payload).decode(charset, errors="replace")
        if cte == "quoted-printable":
            return quopri.decodestring(payload.encode("ascii", errors="replace")).decode(
                charset, errors="replace"
            )
        return payload
    except Exception:
        return payload


# ---------------------------------------------------------------------------
# Header checks (FR-3, FR-4, FR-5)
# ---------------------------------------------------------------------------


def _check_headers(msg, meta: dict) -> list:
    flags = []

    domains = {
        d for d in (
            meta.get("from_domain"),
            meta.get("reply_to_domain"),
            meta.get("return_path_domain"),
        ) if d
    }
    if len(domains) > 1:
        flags.append(_flag(
            "HEADER_DOMAIN_MISMATCH", "headers", "medium",
            f"Домены From/Reply-To/Return-Path не совпадают: {', '.join(sorted(domains))}",
        ))

    display_name = (meta.get("from_display_name") or "").lower()
    from_domain = meta.get("from_domain") or ""
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in display_name and from_domain and from_domain not in legit_domains:
            if not any(from_domain.endswith("." + d) for d in legit_domains):
                flags.append(_flag(
                    "HEADER_DISPLAY_NAME_SPOOF", "headers", "high",
                    f"Имя отправителя похоже на «{brand.title()}», но домен «{from_domain}» "
                    "не принадлежит этой организации",
                ))
                break

    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        for proto in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{proto}=(\w+)", auth_results, re.IGNORECASE)
            if not m:
                continue
            result = m.group(1).lower()
            if result == "fail":
                flags.append(_flag(
                    f"HEADER_AUTH_FAIL_{proto.upper()}", "headers", "high",
                    f"{proto.upper()} проверка не пройдена (fail)",
                ))
            elif result in ("softfail", "none"):
                flags.append(_flag(
                    f"HEADER_AUTH_WEAK_{proto.upper()}", "headers", "medium",
                    f"{proto.upper()} проверка отсутствует или неоднозначна ({result})",
                ))

    return flags


# ---------------------------------------------------------------------------
# Link extraction & checks (FR-6, FR-7)
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_ANCHOR_RE = re.compile(
    r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_DOMAIN_IN_TEXT_RE = re.compile(
    r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE,
)


def _extract_links(plain_text: str, html_text: str) -> dict:
    """Returns {url: anchor_text_or_None}."""
    links = {}
    for url in _URL_RE.findall(plain_text or ""):
        links.setdefault(url.rstrip(".,)>\"'"), None)
    for href, anchor_html in _ANCHOR_RE.findall(html_text or ""):
        anchor_text = unescape(_TAG_RE.sub("", anchor_html)).strip()
        links[href] = anchor_text or None
    for url in _URL_RE.findall(html_text or ""):
        links.setdefault(url.rstrip(".,)>\"'"), None)
    return links


def _hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _check_link(url: str, anchor_text: str | None) -> list:
    flags = []
    host = _hostname(url)
    scheme = urlparse(url).scheme.lower()
    if not host:
        return flags

    if _IP_RE.match(host):
        flags.append(_flag(
            "LINK_IP_ADDRESS", "links", "high",
            f"Ссылка ведёт на IP-адрес вместо домена: {host}",
        ))

    if "xn--" in host:
        flags.append(_flag(
            "LINK_PUNYCODE", "links", "high",
            f"Домен использует punycode (возможна визуальная подмена символов): {host}",
        ))

    registrable = ".".join(host.split(".")[-2:]) if "." in host else host
    if registrable in URL_SHORTENERS or host in URL_SHORTENERS:
        flags.append(_flag(
            "LINK_SHORTENER", "links", "medium",
            f"Ссылка использует сервис сокращения URL: {host}",
        ))

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(_flag(
            "LINK_SUSPICIOUS_TLD", "links", "medium",
            f"Домен использует нетипичную для легитимных писем зону .{tld}: {host}",
        ))

    if scheme == "http":
        flags.append(_flag(
            "LINK_NO_HTTPS", "links", "low",
            f"Ссылка без шифрования (HTTP): {host}",
        ))

    lookalike = _brand_lookalike(host)
    if lookalike:
        flags.append(_flag(
            "LINK_BRAND_LOOKALIKE", "links", "high",
            f"Домен «{host}» похож на «{lookalike}», но не является им",
        ))

    if anchor_text:
        anchor_domains = _DOMAIN_IN_TEXT_RE.findall(anchor_text)
        for ad in anchor_domains:
            ad_norm = ad.lower().rstrip(".")
            if ad_norm != host and not host.endswith("." + ad_norm) and not ad_norm.endswith("." + host):
                flags.append(_flag(
                    "LINK_ANCHOR_MISMATCH", "links", "high",
                    f"Видимый текст ссылки указывает на «{ad_norm}», а фактический адрес — «{host}»",
                ))
                break

    return flags


def _brand_lookalike(host: str) -> str | None:
    if host in ALL_BRAND_DOMAINS:
        return None
    registrable = ".".join(host.split(".")[-2:]) if "." in host else host
    if registrable in ALL_BRAND_DOMAINS:
        return None
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in host:
            return next(iter(legit_domains))
        for legit in legit_domains:
            base = legit.split(".")[0]
            ratio = difflib.SequenceMatcher(None, registrable, legit).ratio()
            if ratio >= 0.75 and registrable != legit:
                return legit
    return None


# ---------------------------------------------------------------------------
# Text checks (FR-8)
# ---------------------------------------------------------------------------


def _check_text(text: str) -> list:
    flags = []
    if not text:
        return flags
    lowered = text.lower()

    if any(re.search(p, lowered, re.IGNORECASE) for p in URGENCY_PATTERNS):
        flags.append(_flag(
            "TEXT_URGENCY", "text", "medium",
            "Текст использует формулировки срочности/давления",
        ))

    if any(re.search(p, lowered, re.IGNORECASE) for p in CREDENTIAL_PATTERNS):
        flags.append(_flag(
            "TEXT_CREDENTIAL_REQUEST", "text", "high",
            "Письмо запрашивает конфиденциальные данные (пароль/карту/PIN)",
        ))

    first_lines = "\n".join(text.strip().splitlines()[:3])
    if any(re.search(p, first_lines, re.IGNORECASE | re.MULTILINE) for p in GENERIC_GREETING_PATTERNS):
        flags.append(_flag(
            "TEXT_GENERIC_GREETING", "text", "low",
            "Обезличенное приветствие вместо обращения по имени",
        ))

    return flags


# ---------------------------------------------------------------------------
# Scoring (FR-9)
# ---------------------------------------------------------------------------


def _flag(flag_id: str, category: str, severity: str, message: str) -> dict:
    return {"id": flag_id, "category": category, "severity": severity, "message": message}


def _compute_score(flags: list) -> int:
    total = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in flags)
    return min(total, 100)


def _verdict_for_score(score: int):
    for threshold, verdict, emoji, label in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict, emoji, label
    return "safe", "🟢", "Безопасно"
