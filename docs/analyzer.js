/* Phishing Scanner — browser port of phishing_analyzer.py.
 * Pure client-side heuristic analysis. No network calls, no data storage.
 * Kept in sync with the Python engine's rules and scoring. */
(function (global) {
  "use strict";

  const SEVERITY_WEIGHTS = { high: 25, medium: 12, low: 5 };

  const VERDICT_THRESHOLDS = [
    [60, "high", "🔴", "Высокий риск"],
    [30, "medium", "🟠", "Средний риск"],
    [1, "low", "🟡", "Низкий риск"],
    [0, "safe", "🟢", "Безопасно"],
  ];

  const URL_SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "clck.ru", "vk.cc",
    "s.id", "rb.gy", "shorte.st", "adf.ly",
  ]);

  const SUSPICIOUS_TLDS = new Set([
    "xyz", "top", "club", "work", "click", "link", "country", "gq", "tk",
    "ml", "cf", "ga", "loan", "win", "review", "date", "stream", "icu",
    "fit", "bid", "party", "men", "kim", "cricket", "accountant",
  ]);

  const KNOWN_BRANDS = {
    paypal: ["paypal.com"],
    apple: ["apple.com", "icloud.com"],
    microsoft: ["microsoft.com", "outlook.com", "office.com", "live.com"],
    google: ["google.com", "gmail.com"],
    amazon: ["amazon.com"],
    netflix: ["netflix.com"],
    facebook: ["facebook.com", "fb.com"],
    instagram: ["instagram.com"],
    dhl: ["dhl.com", "dhl.de"],
    fedex: ["fedex.com"],
    ebay: ["ebay.com"],
    "сбербанк": ["sberbank.ru", "sber.ru"],
    sberbank: ["sberbank.ru", "sber.ru"],
    "тинькофф": ["tinkoff.ru", "tbank.ru"],
    tinkoff: ["tinkoff.ru", "tbank.ru"],
    "госуслуги": ["gosuslugi.ru"],
    gosuslugi: ["gosuslugi.ru"],
    "альфа-банк": ["alfabank.ru"],
    alfabank: ["alfabank.ru"],
  };
  const ALL_BRAND_DOMAINS = new Set();
  for (const domains of Object.values(KNOWN_BRANDS)) {
    domains.forEach((d) => ALL_BRAND_DOMAINS.add(d));
  }

  // JavaScript's \b and \w are ASCII-only, so Cyrillic keywords use an
  // explicit word class W = [\wа-яёa-z0-9] and lookaround boundaries B.
  const W = "[\\wа-яёА-ЯЁ]";
  const B = "(?![\\wа-яёА-ЯЁ])";     // trailing boundary (not followed by word char)
  const Bs = "(?<![\\wа-яёА-ЯЁ])";   // leading boundary (not preceded by word char)

  const URGENCY_PATTERNS = [
    new RegExp(Bs + "сроч" + W + "*", "i"),
    new RegExp(Bs + "немедленн" + W + "*", "i"),
    new RegExp(Bs + "блокир" + W + "*", "i"),
    new RegExp(Bs + "приостановлен" + W + "*", "i"),
    new RegExp(Bs + "ограничен" + W + "* доступ", "i"),
    new RegExp(Bs + "последн" + W + "* (шанс|день|напомин" + W + "*)", "i"),
    new RegExp(Bs + "аккаунт.{0,15}(заблок|огранич|приостановлен)", "i"),
    /\burgent\b/i, /\bimmediately\b/i, /\bact now\b/i, /\bexpir(e|es|ed|ing)\b/i,
    /\bsuspend(ed|ing)?\b/i, /\blimited time\b/i, /\bverify your account\b/i,
    /\bwithin 24 hours\b/i, /\byour account (has been|will be) (locked|suspended|disabled)\b/i,
  ];

  const CREDENTIAL_PATTERNS = [
    new RegExp(Bs + "парол" + W + "*", "i"),
    new RegExp(Bs + "номер карты" + B, "i"),
    /\bcvv\b/i, /\bcvc\b/i,
    new RegExp(Bs + "пин-?код" + W + "*", "i"),
    new RegExp(Bs + "дан(ные|ных) карт" + W + "*", "i"),
    new RegExp(Bs + "подтверди" + W + "* учетн" + W + "* запис" + W + "*", "i"),
    /\blogin and password\b/i, /\bpassword\b/i, /\bcredit card number\b/i,
    /\bsocial security number\b/i, /\bssn\b/i, /\bconfirm your (account|identity|password)\b/i,
    /\bbank account (number|details)\b/i, /\bwire transfer\b/i,
  ];

  const GENERIC_GREETING_PATTERNS = [
    /^\s*dear (customer|user|sir|madam|sir\/madam|valued customer)\b/im,
    new RegExp("^\\s*уважаем" + W + "* (клиент|пользователь|пользователи)" + B, "im"),
    /^\s*здравствуйте!?\s*$/im,
    /^\s*hello,?\s*$/im,
  ];

  const URL_RE = /https?:\/\/[^\s<>"']+/gi;
  const ANCHOR_RE = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  const TAG_RE = /<[^>]+>/g;
  const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
  const DOMAIN_IN_TEXT_RE = /\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/gi;

  function flag(id, category, severity, message) {
    return { id, category, severity, message };
  }

  // --- Raw email detection & lightweight parsing -------------------------

  function looksLikeRawEmail(text) {
    const head = text.slice(0, 4000);
    const hasFrom = /^from:\s*\S/im.test(head);
    const hasSubject = /^subject:\s*\S/im.test(head);
    const hasTo = /^to:\s*\S/im.test(head);
    return [hasFrom, hasSubject, hasTo].filter(Boolean).length >= 2;
  }

  function decodeEncodedWord(value) {
    if (!value) return "";
    // Decode RFC 2047 =?charset?B/Q?...?= words (utf-8 best-effort).
    return value.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, function (_, charset, enc, data) {
      try {
        if (enc.toUpperCase() === "B") {
          return utf8Decode(atob(data));
        }
        const q = data.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_, h) =>
          String.fromCharCode(parseInt(h, 16))
        );
        return utf8Decode(q);
      } catch (e) {
        return data;
      }
    });
  }

  function utf8Decode(bytesStr) {
    try {
      return decodeURIComponent(escape(bytesStr));
    } catch (e) {
      return bytesStr;
    }
  }

  function parseHeaders(raw) {
    const sepMatch = raw.match(/\r?\n\r?\n/);
    const headerBlock = sepMatch ? raw.slice(0, sepMatch.index) : raw;
    const body = sepMatch ? raw.slice(sepMatch.index + sepMatch[0].length) : "";
    // Unfold headers (continuation lines start with whitespace).
    const unfolded = headerBlock.replace(/\r?\n[ \t]+/g, " ");
    const headers = {};
    unfolded.split(/\r?\n/).forEach((line) => {
      const m = line.match(/^([\w-]+):\s*(.*)$/);
      if (m) {
        const key = m[1].toLowerCase();
        if (!(key in headers)) headers[key] = m[2];
      }
    });
    return { headers, body };
  }

  function addrDomain(headerValue) {
    if (!headerValue) return "";
    const m = headerValue.match(/[^\s<>@]+@([^\s<>]+)/);
    if (!m) return "";
    return m[1].trim().toLowerCase().replace(/\.$/, "");
  }

  function displayName(headerValue) {
    if (!headerValue) return "";
    const quoted = headerValue.match(/"([^"]+)"/);
    if (quoted) return quoted[1];
    const before = headerValue.split("<")[0];
    return before.trim();
  }

  function decodeBody(body, headers) {
    const cte = (headers["content-transfer-encoding"] || "").trim().toLowerCase();
    try {
      if (cte === "base64") {
        return utf8Decode(atob(body.replace(/\s+/g, "")));
      }
      if (cte === "quoted-printable") {
        const decoded = body
          .replace(/=\r?\n/g, "")
          .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
        return utf8Decode(decoded);
      }
    } catch (e) {
      return body;
    }
    return body;
  }

  // --- Header checks -----------------------------------------------------

  function checkHeaders(headers, meta) {
    const flags = [];
    const domains = new Set(
      [meta.from_domain, meta.reply_to_domain, meta.return_path_domain].filter(Boolean)
    );
    if (domains.size > 1) {
      flags.push(flag("HEADER_DOMAIN_MISMATCH", "headers", "medium",
        `Домены From/Reply-To/Return-Path не совпадают: ${[...domains].sort().join(", ")}`));
    }

    const dname = (meta.from_display_name || "").toLowerCase();
    const fromDomain = meta.from_domain || "";
    for (const [brand, legit] of Object.entries(KNOWN_BRANDS)) {
      if (dname.includes(brand) && fromDomain && !legit.includes(fromDomain)) {
        if (!legit.some((d) => fromDomain.endsWith("." + d))) {
          flags.push(flag("HEADER_DISPLAY_NAME_SPOOF", "headers", "high",
            `Имя отправителя похоже на «${title(brand)}», но домен «${fromDomain}» не принадлежит этой организации`));
          break;
        }
      }
    }

    const auth = headers["authentication-results"] || "";
    if (auth) {
      ["spf", "dkim", "dmarc"].forEach((proto) => {
        const m = auth.match(new RegExp(proto + "=(\\w+)", "i"));
        if (!m) return;
        const result = m[1].toLowerCase();
        if (result === "fail") {
          flags.push(flag(`HEADER_AUTH_FAIL_${proto.toUpperCase()}`, "headers", "high",
            `${proto.toUpperCase()} проверка не пройдена (fail)`));
        } else if (result === "softfail" || result === "none") {
          flags.push(flag(`HEADER_AUTH_WEAK_${proto.toUpperCase()}`, "headers", "medium",
            `${proto.toUpperCase()} проверка отсутствует или неоднозначна (${result})`));
        }
      });
    }
    return flags;
  }

  // --- Link extraction & checks -----------------------------------------

  function extractLinks(plainText, htmlText) {
    const links = new Map();
    (plainText.match(URL_RE) || []).forEach((url) => {
      const clean = url.replace(/[.,)>"']+$/, "");
      if (!links.has(clean)) links.set(clean, null);
    });
    let m;
    ANCHOR_RE.lastIndex = 0;
    while ((m = ANCHOR_RE.exec(htmlText)) !== null) {
      const anchorText = unescapeHtml(m[2].replace(TAG_RE, "")).trim();
      links.set(m[1], anchorText || null);
    }
    (htmlText.match(URL_RE) || []).forEach((url) => {
      const clean = url.replace(/[.,)>"']+$/, "");
      if (!links.has(clean)) links.set(clean, null);
    });
    return links;
  }

  function hostname(url) {
    try {
      return (new URL(url).hostname || "").toLowerCase();
    } catch (e) {
      return "";
    }
  }

  function scheme(url) {
    try {
      return new URL(url).protocol.replace(":", "").toLowerCase();
    } catch (e) {
      return "";
    }
  }

  function checkLink(url, anchorText) {
    const flags = [];
    const host = hostname(url);
    if (!host) return flags;

    if (IP_RE.test(host)) {
      flags.push(flag("LINK_IP_ADDRESS", "links", "high",
        `Ссылка ведёт на IP-адрес вместо домена: ${host}`));
    }
    if (host.includes("xn--")) {
      flags.push(flag("LINK_PUNYCODE", "links", "high",
        `Домен использует punycode (возможна визуальная подмена символов): ${host}`));
    }

    const parts = host.split(".");
    const registrable = parts.length >= 2 ? parts.slice(-2).join(".") : host;
    if (URL_SHORTENERS.has(registrable) || URL_SHORTENERS.has(host)) {
      flags.push(flag("LINK_SHORTENER", "links", "medium",
        `Ссылка использует сервис сокращения URL: ${host}`));
    }

    const tld = host.includes(".") ? parts[parts.length - 1] : "";
    if (SUSPICIOUS_TLDS.has(tld)) {
      flags.push(flag("LINK_SUSPICIOUS_TLD", "links", "medium",
        `Домен использует нетипичную для легитимных писем зону .${tld}: ${host}`));
    }

    if (scheme(url) === "http") {
      flags.push(flag("LINK_NO_HTTPS", "links", "low",
        `Ссылка без шифрования (HTTP): ${host}`));
    }

    const lookalike = brandLookalike(host);
    if (lookalike) {
      flags.push(flag("LINK_BRAND_LOOKALIKE", "links", "high",
        `Домен «${host}» похож на «${lookalike}», но не является им`));
    }

    if (anchorText) {
      const anchorDomains = anchorText.match(DOMAIN_IN_TEXT_RE) || [];
      for (const ad of anchorDomains) {
        const adNorm = ad.toLowerCase().replace(/\.$/, "");
        if (adNorm !== host && !host.endsWith("." + adNorm) && !adNorm.endsWith("." + host)) {
          flags.push(flag("LINK_ANCHOR_MISMATCH", "links", "high",
            `Видимый текст ссылки указывает на «${adNorm}», а фактический адрес — «${host}»`));
          break;
        }
      }
    }
    return flags;
  }

  function brandLookalike(host) {
    if (ALL_BRAND_DOMAINS.has(host)) return null;
    const parts = host.split(".");
    const registrable = parts.length >= 2 ? parts.slice(-2).join(".") : host;
    if (ALL_BRAND_DOMAINS.has(registrable)) return null;
    for (const [brand, legitDomains] of Object.entries(KNOWN_BRANDS)) {
      if (host.includes(brand)) return legitDomains[0];
      for (const legit of legitDomains) {
        const ratio = similarity(registrable, legit);
        if (ratio >= 0.75 && registrable !== legit) return legit;
      }
    }
    return null;
  }

  // Approximates difflib.SequenceMatcher.ratio() closely enough for the demo.
  function similarity(a, b) {
    if (!a && !b) return 1;
    const matches = matchingBlocks(a, b);
    return (2.0 * matches) / (a.length + b.length);
  }

  function matchingBlocks(a, b) {
    // Longest common subsequence length (proxy for total matched chars).
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1] + 1
          : Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
    return dp[m][n];
  }

  // --- Text checks -------------------------------------------------------

  function checkText(text) {
    const flags = [];
    if (!text) return flags;
    const lowered = text.toLowerCase();

    if (URGENCY_PATTERNS.some((p) => p.test(lowered))) {
      flags.push(flag("TEXT_URGENCY", "text", "medium",
        "Текст использует формулировки срочности/давления"));
    }
    if (CREDENTIAL_PATTERNS.some((p) => p.test(lowered))) {
      flags.push(flag("TEXT_CREDENTIAL_REQUEST", "text", "high",
        "Письмо запрашивает конфиденциальные данные (пароль/карту/PIN)"));
    }
    const firstLines = text.trim().split(/\r?\n/).slice(0, 3).join("\n");
    if (GENERIC_GREETING_PATTERNS.some((p) => p.test(firstLines))) {
      flags.push(flag("TEXT_GENERIC_GREETING", "text", "low",
        "Обезличенное приветствие вместо обращения по имени"));
    }
    return flags;
  }

  // --- Scoring -----------------------------------------------------------

  function computeScore(flags) {
    const total = flags.reduce((sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] || 0), 0);
    return Math.min(total, 100);
  }

  function verdictForScore(score) {
    for (const [threshold, verdict, emoji, label] of VERDICT_THRESHOLDS) {
      if (score >= threshold) return [verdict, emoji, label];
    }
    return ["safe", "🟢", "Безопасно"];
  }

  // --- Helpers -----------------------------------------------------------

  function unescapeHtml(s) {
    const el = document.createElement("textarea");
    el.innerHTML = s;
    return el.value;
  }

  function title(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  // --- Public entrypoint -------------------------------------------------

  function analyzeEmail(rawInput) {
    rawInput = rawInput || "";
    const isRaw = looksLikeRawEmail(rawInput);

    const flags = [];
    let meta = {};
    let plain = rawInput;
    let html = "";

    if (isRaw) {
      const parsed = parseHeaders(rawInput);
      const h = parsed.headers;
      meta = {
        from: decodeEncodedWord(h["from"] || ""),
        from_display_name: decodeEncodedWord(displayName(h["from"] || "")),
        from_domain: addrDomain(h["from"] || ""),
        reply_to_domain: addrDomain(h["reply-to"] || ""),
        return_path_domain: addrDomain(h["return-path"] || ""),
        subject: decodeEncodedWord(h["subject"] || ""),
      };
      flags.push(...checkHeaders(h, meta));
      const decodedBody = decodeBody(parsed.body, h);
      const ctype = (h["content-type"] || "").toLowerCase();
      if (ctype.includes("text/html")) {
        html = decodedBody;
      } else {
        plain = decodedBody;
      }
    }

    const combined = [plain, html].filter(Boolean).join("\n");
    const links = extractLinks(plain || "", html || "");
    const linkResults = [];
    for (const [url, anchor] of links) {
      const linkFlags = checkLink(url, anchor);
      linkResults.push({ url, domain: hostname(url), flags: linkFlags });
      flags.push(...linkFlags);
    }

    flags.push(...checkText(combined));

    const score = computeScore(flags);
    const [verdict, emoji, label] = verdictForScore(score);

    return {
      score,
      verdict,
      verdict_emoji: emoji,
      verdict_label: label,
      is_raw_email: isRaw,
      flags,
      links: linkResults,
      total_links: linkResults.length,
      meta,
    };
  }

  global.PhishingAnalyzer = { analyzeEmail };
})(window);
