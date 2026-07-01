"""Regression tests for phishing_analyzer.

Encodes the PRD success metric: 0 false positives on clean mail, score >= 60
on clear phishing samples.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishing_analyzer import analyze_email

CLEAN_EMAIL = """From: Alice Smith <alice@company.com>
To: Bob Jones <bob@company.com>
Subject: Meeting notes from today
Reply-To: alice@company.com
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass

Hi Bob,

Attached are the notes from today's sync. Let me know if I missed anything.

See you tomorrow,
Alice
"""

CLEAN_NEWSLETTER = """From: Company Updates <updates@techblog.com>
To: subscriber@example.com
Subject: This week in tech
Reply-To: updates@techblog.com
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass

Hi there,

Here is this week's roundup of articles from our blog at https://techblog.com/weekly.

Thanks for reading,
The Techblog Team
"""

PHISHING_PAYPAL = """From: PayPal Support <no-reply@paypal-security-alert.top>
To: victim@example.com
Subject: Urgent: Your account will be suspended
Reply-To: verify@paypal-security-alert.top
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail

Dear Customer,

Your account has been suspended. You must verify your account immediately
by clicking below within 24 hours or your account will be locked.

<a href="http://192.168.1.1/verify">https://paypal.com/verify</a>

Please confirm your password and card number now.
"""

PHISHING_BANK_LOOKALIKE = """From: Sberbank Security <alert@sberbank-verify.xyz>
To: victim@example.com
Subject: Срочно! Ваш аккаунт заблокирован
Reply-To: support@sberbank-verify.xyz

Уважаемый клиент,

Ваш аккаунт временно заблокирован. Подтвердите пароль и номер карты
немедленно по ссылке: http://bit.ly/sber-verify
"""


class AnalyzeEmailTests(unittest.TestCase):
    def test_clean_email_has_zero_score(self):
        result = analyze_email(CLEAN_EMAIL)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["verdict"], "safe")
        self.assertEqual(result["flags"], [])

    def test_clean_newsletter_has_zero_score(self):
        result = analyze_email(CLEAN_NEWSLETTER)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["verdict"], "safe")

    def test_paypal_phishing_scores_high(self):
        result = analyze_email(PHISHING_PAYPAL)
        self.assertGreaterEqual(result["score"], 60)
        self.assertEqual(result["verdict"], "high")
        flag_ids = {f["id"] for f in result["flags"]}
        self.assertIn("HEADER_DISPLAY_NAME_SPOOF", flag_ids)
        self.assertIn("LINK_IP_ADDRESS", flag_ids)
        self.assertIn("TEXT_CREDENTIAL_REQUEST", flag_ids)

    def test_bank_lookalike_scores_high(self):
        result = analyze_email(PHISHING_BANK_LOOKALIKE)
        self.assertGreaterEqual(result["score"], 60)
        flag_ids = {f["id"] for f in result["flags"]}
        self.assertIn("TEXT_URGENCY", flag_ids)
        self.assertIn("TEXT_CREDENTIAL_REQUEST", flag_ids)
        self.assertIn("LINK_SHORTENER", flag_ids)

    def test_plain_text_without_headers_is_not_raw_email(self):
        result = analyze_email("Hey, just checking in about lunch tomorrow.")
        self.assertFalse(result["is_raw_email"])
        self.assertEqual(result["score"], 0)

    def test_empty_input_does_not_error(self):
        result = analyze_email("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["verdict"], "safe")


if __name__ == "__main__":
    unittest.main()
