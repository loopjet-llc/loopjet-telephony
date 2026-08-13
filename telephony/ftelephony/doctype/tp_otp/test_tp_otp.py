# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# See license.txt

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import add_to_date, now_datetime

from telephony.ftelephony.doctype.tp_otp_settings.tp_otp_settings import TPOTPSettings
from telephony.ftelephony.doctype.tp_twilio_settings.tp_twilio_settings import (
    TPTwilioSettings,
)
from telephony.otp import GENERIC_FAILURE
from telephony.twilio.sms import REDACTED_MESSAGE

EXTRA_TEST_RECORD_DEPENDENCIES = []
IGNORE_TEST_RECORD_DEPENDENCIES = []

TEST_SMS_FROM_NUMBER = "+15005550006"

PHONE_VERIFY = "+911234500001"
PHONE_ATTEMPTS = "+911234500002"
PHONE_EXPIRY = "+911234500003"
PHONE_BUDGET = "+911234500004"
PHONE_RESET = "+911234500005"
PHONE_NORMALIZE = "+911234500006"
PHONE_REDACT = "+911234500007"
TEST_EMAIL = "test-otp@example.com"

TEST_RECIPIENTS = [
    PHONE_VERIFY,
    PHONE_ATTEMPTS,
    PHONE_EXPIRY,
    PHONE_BUDGET,
    PHONE_RESET,
    PHONE_NORMALIZE,
    PHONE_REDACT,
    TEST_EMAIL,
]


class IntegrationTestTPOTP(IntegrationTestCase):
    """Integration tests for TP OTP, exercising the SMS and Email OTP flows
    end-to-end with the actual Twilio/email dispatch mocked out."""

    def setUp(self):
        super().setUp()

        # TP OTP Settings.validate() confirms sms_from_number against the live
        # Twilio account. These tests never reach Twilio, so stub that one
        # check rather than skipping validation wholesale — the OTP parameter
        # validation still runs.
        patcher = patch.object(
            TPOTPSettings, "validate_sms_from_number", return_value=None
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        # TP Twilio Settings.validate() authenticates against the live Twilio
        # API and on_update() provisions API keys there; neither is reachable
        # from tests. Stub both so change_settings can drive the doc normally.
        for method in ("validate_twilio_account", "on_update"):
            twilio_patcher = patch.object(TPTwilioSettings, method, return_value=None)
            twilio_patcher.start()
            self.addCleanup(twilio_patcher.stop)

        # validate() also requires TP Twilio Settings to be enabled.
        twilio_settings = self.change_settings("TP Twilio Settings", {"enabled": 1})
        twilio_settings.__enter__()
        self.addCleanup(twilio_settings.__exit__, None, None, None)
        frappe.clear_cache(doctype="TP Twilio Settings")

        settings = self.change_settings(
            "TP OTP Settings",
            {
                "enabled": 1,
                "enable_email_otp": 1,
                "sms_from_number": TEST_SMS_FROM_NUMBER,
                "otp_length": 6,
                "otp_expiry_in_seconds": 300,
                "otp_max_attempts": 2,
            },
        )
        settings.__enter__()
        self.addCleanup(settings.__exit__, None, None, None)
        frappe.clear_cache(doctype="TP OTP Settings")

        self.addCleanup(self._delete_test_records)

    def _delete_test_records(self):
        frappe.db.delete("TP OTP", {"recipient": ["in", TEST_RECIPIENTS]})
        frappe.db.delete("TP SMS Log", {"to": ["in", TEST_RECIPIENTS]})

    def _log_sent_sms(self, to, message, purpose="OTP"):
        """Stand in for dispatch_sms, but still write a real TP SMS Log so the
        redaction behaviour under test is exercised."""
        from telephony.twilio.sms import create_sms_log

        return create_sms_log(
            to, TEST_SMS_FROM_NUMBER, message, purpose, "Sent", sid="SM_test"
        )

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_sms_otp_generate_and_verify(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        result = generate_otp(phone_number=PHONE_VERIFY, purpose="Verification")
        self.assertTrue(result["sent"])
        mock_dispatch_sms.assert_called_once()

        wrong = verify_otp(
            phone_number=PHONE_VERIFY, otp="000000", purpose="Verification"
        )
        self.assertEqual(wrong, GENERIC_FAILURE)

        correct = verify_otp(
            phone_number=PHONE_VERIFY, otp="123456", purpose="Verification"
        )
        self.assertEqual(correct, {"verified": True})

        # a verified OTP cannot be replayed
        replay = verify_otp(
            phone_number=PHONE_VERIFY, otp="123456", purpose="Verification"
        )
        self.assertEqual(replay, GENERIC_FAILURE)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_generate_response_never_carries_the_code(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The response is returned to unauthenticated callers, so it must not
        echo the OTP back under any site configuration."""
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        result = generate_otp(phone_number=PHONE_VERIFY, purpose="Verification")
        self.assertNotIn("otp", result)
        self.assertEqual(set(result), {"sent", "expires_in"})

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="654321")
    def test_sms_otp_max_attempts(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_ATTEMPTS, purpose="Login")

        # otp_max_attempts is set to 2 in setUp
        for _ in range(2):
            result = verify_otp(
                phone_number=PHONE_ATTEMPTS, otp="000000", purpose="Login"
            )
            self.assertEqual(result, GENERIC_FAILURE)

        locked_out = verify_otp(
            phone_number=PHONE_ATTEMPTS, otp="654321", purpose="Login"
        )
        self.assertEqual(locked_out, GENERIC_FAILURE)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="222333")
    def test_regenerating_otp_does_not_reset_attempt_budget(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """Requesting a fresh OTP must not hand out a new attempt budget while
        the previous one is still live, else the max-attempts cap is toothless."""
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_BUDGET, purpose="Login")
        for _ in range(2):
            verify_otp(phone_number=PHONE_BUDGET, otp="000000", purpose="Login")

        # budget exhausted
        self.assertEqual(
            verify_otp(phone_number=PHONE_BUDGET, otp="222333", purpose="Login"),
            GENERIC_FAILURE,
        )

        # Resending is refused outright rather than issuing a code that starts
        # at the cap: no SMS is paid for, and no new row is created to carry a
        # refreshed expires_at.
        with self.assertRaises(frappe.ValidationError):
            generate_otp(phone_number=PHONE_BUDGET, purpose="Login")

        carried = frappe.db.get_value(
            "TP OTP",
            {"recipient": PHONE_BUDGET, "is_verified": 0},
            "attempts",
            order_by="creation desc",
        )
        self.assertEqual(carried, 2)
        # the refused resend must not have added a row
        self.assertEqual(
            frappe.db.count("TP OTP", {"recipient": PHONE_BUDGET, "is_verified": 0}), 1
        )

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="222333")
    def test_resending_while_locked_out_does_not_extend_the_lockout(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """Carrying attempts forward onto a row with a *fresh* expires_at made
        the lockout self-perpetuating: every resend inside the window pushed the
        expiry a full window further out while billing for a dead code, so a user
        who reacted by retrying — the normal reaction — never got back in."""
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_BUDGET, purpose="Login")
        for _ in range(2):
            verify_otp(phone_number=PHONE_BUDGET, otp="000000", purpose="Login")

        original_expiry = frappe.db.get_value(
            "TP OTP",
            {"recipient": PHONE_BUDGET, "is_verified": 0},
            "expires_at",
            order_by="creation desc",
        )

        # keep retrying across the window, as a locked-out user would
        for offset in (60, 120, 240):
            with self.freeze_time(add_to_date(now_datetime(), seconds=offset)):
                with self.assertRaises(frappe.ValidationError):
                    generate_otp(phone_number=PHONE_BUDGET, purpose="Login")

        self.assertEqual(
            frappe.db.get_value(
                "TP OTP",
                {"recipient": PHONE_BUDGET, "is_verified": 0},
                "expires_at",
                order_by="creation desc",
            ),
            original_expiry,
        )
        # no SMS was paid for by any of the refused resends
        self.assertEqual(mock_dispatch_sms.call_count, 1)

        # and the lockout drains on schedule despite the retries
        with self.freeze_time(add_to_date(now_datetime(), seconds=301)):
            generate_otp(phone_number=PHONE_BUDGET, purpose="Login")
            self.assertEqual(
                verify_otp(phone_number=PHONE_BUDGET, otp="222333", purpose="Login"),
                {"verified": True},
            )

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="333444")
    def test_attempt_budget_resets_once_window_lapses(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The carry-forward above must not become a permanent lockout: once the
        previous OTP is no longer live, a fresh request starts clean."""
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_RESET, purpose="Login")
        for _ in range(2):
            verify_otp(phone_number=PHONE_RESET, otp="000000", purpose="Login")

        # otp_expiry_in_seconds is 300 in setUp
        with self.freeze_time(add_to_date(now_datetime(), seconds=301)):
            generate_otp(phone_number=PHONE_RESET, purpose="Login")
            self.assertEqual(
                verify_otp(phone_number=PHONE_RESET, otp="333444", purpose="Login"),
                {"verified": True},
            )

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="111222")
    def test_sms_otp_expiry(self, mock_generate_code, mock_dispatch_sms):
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_EXPIRY, purpose="Login")

        # otp_expiry_in_seconds is 300 in setUp
        with self.freeze_time(add_to_date(now_datetime(), seconds=301)):
            expired = verify_otp(
                phone_number=PHONE_EXPIRY, otp="111222", purpose="Login"
            )

        self.assertEqual(expired, GENERIC_FAILURE)

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_otp_body_is_not_written_to_sms_log(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """TP SMS Log is readable by TP Agent and kept for 90 days, so storing
        the rendered code there would defeat hashing it in TP OTP."""
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number=PHONE_REDACT, purpose="Verification")

        logged = frappe.db.get_value("TP SMS Log", {"to": PHONE_REDACT}, "message")
        self.assertEqual(logged, REDACTED_MESSAGE)
        self.assertNotIn("123456", logged)

    def test_general_sms_body_is_retained_in_log(self):
        """Redaction is scoped to OTP traffic; ordinary sends stay auditable."""
        from telephony.twilio.sms import create_sms_log

        log = create_sms_log(
            PHONE_REDACT, TEST_SMS_FROM_NUMBER, "hello there", "General", "Sent"
        )
        self.assertEqual(log.message, "hello there")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_rate_limit_key_is_normalized(self, mock_generate_code, mock_dispatch_sms):
        """frappe.rate_limit buckets on form_dict[key] verbatim, so the key has
        to be canonical or the send cap is bypassable by reformatting."""
        from telephony.otp import RATE_LIMIT_FIELD
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        self.addCleanup(frappe.form_dict.pop, "phone_number", None)
        self.addCleanup(frappe.form_dict.pop, RATE_LIMIT_FIELD, None)
        frappe.form_dict["phone_number"] = "+91 12345-00006"

        generate_otp(phone_number="+91 12345-00006", purpose="Verification")

        self.assertEqual(frappe.form_dict["phone_number"], PHONE_NORMALIZE)
        self.assertEqual(
            frappe.form_dict[RATE_LIMIT_FIELD], f"sms:generate:{PHONE_NORMALIZE}"
        )

    def test_unusable_recipients_share_one_bucket(self):
        """A recipient that cannot be canonicalized must not become its own
        bucket: with the raw string as the key, varying the garbage minted fresh
        quota against the address it would ultimately resolve to. They also must
        not leave the key *empty*, which makes rate_limit throw its own "Either
        key or IP flag is required" in place of the endpoint's message."""
        from telephony.email_otp import clean_email
        from telephony.otp import INVALID_RECIPIENT, RATE_LIMIT_FIELD, rate_limit_bucket

        self.addCleanup(frappe.form_dict.pop, "email", None)
        self.addCleanup(frappe.form_dict.pop, RATE_LIMIT_FIELD, None)

        @rate_limit_bucket("email", clean_email, "email:generate")
        def endpoint(email=None):
            return frappe.form_dict[RATE_LIMIT_FIELD]

        buckets = set()
        for spelling in (
            f"{TEST_EMAIL},,",
            f"{TEST_EMAIL},,,",
            f"{TEST_EMAIL} other@example.com",
            "",
        ):
            frappe.form_dict["email"] = spelling
            buckets.add(endpoint(email=spelling))

        self.assertEqual(buckets, {f"email:generate:{INVALID_RECIPIENT}"})

    @patch("telephony.email_otp.dispatch_email_otp")
    def test_email_bucket_agrees_with_the_recipient_that_would_be_stored(
        self, mock_dispatch_email
    ):
        """clean_email used to fall back to the raw string when parseaddr bailed,
        while validate_email_address's per-piece fallback still resolved it — so
        "victim@x.com,," bucketed separately but delivered to victim@x.com, and
        each extra comma bought another untouched 5-per-10-minutes."""
        from telephony.email_otp import clean_email
        from telephony.email_otp import generate_otp as generate_email_otp

        for spoofed in (f"{TEST_EMAIL},,", f"{TEST_EMAIL},,,,"):
            self.assertEqual(clean_email(spoofed), "")
            with self.assertRaises(frappe.ValidationError):
                generate_email_otp(email=spoofed, purpose="Verification")

        mock_dispatch_email.assert_not_called()

        # The invariant, stated directly: for anything that *is* accepted, the
        # bucket clean_email produces has to be the recipient that gets stored.
        # parseaddr resolves more than it rejects — "a@x.com," loses the comma,
        # "a@x.com x" becomes "a@x.comx" — and that is fine as long as the two
        # sides agree, which is what this checks.
        from telephony.email_otp import validate_single_email

        for accepted in (TEST_EMAIL, f"{TEST_EMAIL},", f" {TEST_EMAIL.upper()} "):
            stored = validate_single_email(accepted)
            self.assertEqual(clean_email(accepted), stored, accepted)
            self.assertEqual(clean_email(stored), stored, accepted)

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="999888")
    def test_email_otp_generate_verify_and_channel_isolation(
        self, mock_generate_code, mock_dispatch_email
    ):
        from telephony.email_otp import generate_otp as generate_email_otp
        from telephony.email_otp import verify_otp as verify_email_otp
        from telephony.otp import verify_otp_record

        result = generate_email_otp(email=TEST_EMAIL, purpose="Verification")
        self.assertTrue(result["sent"])
        mock_dispatch_email.assert_called_once()

        # an OTP created on the Email channel must not be found when checked
        # against SMS
        cross_channel = verify_otp_record(
            TEST_EMAIL, "SMS", "999888", "Verification", 5
        )
        self.assertEqual(cross_channel, GENERIC_FAILURE)

        correct = verify_email_otp(
            email=TEST_EMAIL, otp="999888", purpose="Verification"
        )
        self.assertEqual(correct, {"verified": True})

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="999888")
    def test_email_otp_is_case_insensitive(
        self, mock_generate_code, mock_dispatch_email
    ):
        """Case variants must resolve to one recipient, both for storage and for
        rate-limit bucketing."""
        from telephony.email_otp import generate_otp as generate_email_otp
        from telephony.email_otp import verify_otp as verify_email_otp

        generate_email_otp(email="Test-OTP@Example.COM", purpose="Verification")

        stored = frappe.db.get_value(
            "TP OTP", {"recipient": TEST_EMAIL, "channel": "Email"}, "recipient"
        )
        self.assertEqual(stored, TEST_EMAIL)

        correct = verify_email_otp(
            email=TEST_EMAIL, otp="999888", purpose="Verification"
        )
        self.assertEqual(correct, {"verified": True})

    @patch("telephony.email_otp.dispatch_email_otp")
    def test_email_otp_rejects_multiple_addresses(self, mock_dispatch_email):
        """validate_email_address() accepts a comma-separated list and returns
        it re-joined, which would store two addresses as one recipient."""
        from telephony.email_otp import generate_otp as generate_email_otp

        with self.assertRaises(frappe.ValidationError):
            generate_email_otp(
                email=f"{TEST_EMAIL}, other@example.com", purpose="Verification"
            )

        mock_dispatch_email.assert_not_called()

    @patch("telephony.email_otp.dispatch_email_otp")
    def test_email_otp_rejects_newline_separated_addresses(self, mock_dispatch_email):
        """A newline is the separator that slips past a split_emails() count:
        split_emails collapses \\n to a space before splitting, while
        validate_email_address turns it into a comma and returns both."""
        from telephony.email_otp import generate_otp as generate_email_otp

        for separator in ("\n", "\r"):
            with self.assertRaises(frappe.ValidationError):
                generate_email_otp(
                    email=f"{TEST_EMAIL}{separator}other@example.com",
                    purpose="Verification",
                )

        mock_dispatch_email.assert_not_called()

    def test_email_otp_is_redacted_from_the_email_queue(self):
        """Email Queue keeps the rendered body for 30 days, so the queued OTP
        must not outlive its own expiry in cleartext."""
        import inspect

        from telephony.email_otp import dispatch_email_otp

        with patch("frappe.sendmail") as mock_sendmail:
            dispatch_email_otp(TEST_EMAIL, "Your OTP is 123456.", "Code")

        _, kwargs = mock_sendmail.call_args
        self.assertTrue(kwargs.get("redact_message_after_send"))
        # guard against the kwarg being silently dropped by a frappe upgrade
        self.assertIn(
            "redact_message_after_send", inspect.signature(frappe.sendmail).parameters
        )

    def test_clean_phone_number_rejects_non_ascii_digits(self):
        """str.isdigit() is true for fullwidth/Arabic-Indic digits, which
        MariaDB's utf8mb4_unicode_ci then compares equal to their ASCII form —
        so they must not survive normalization. Rejected, not dropped: dropping
        them would leave a shorter number that is still deliverable."""
        from telephony.twilio.sms import clean_phone_number

        # fullwidth ９１ and Arabic-Indic ٩١ both pass str.isdigit()
        self.assertEqual(clean_phone_number("+９１1234500001"), "")
        self.assertEqual(clean_phone_number("+٩١1234500001"), "")
        self.assertEqual(clean_phone_number("+91 12345-00001"), "+911234500001")

    def test_clean_phone_number_rejects_rather_than_absorbing_stray_input(self):
        """Silently dropping unexpected characters rewrites one number into a
        different, deliverable one — so the OTP reaches a stranger who never
        asked for it. "1. +919876543210" used to yield +1919876543210."""
        from telephony.twilio.sms import clean_phone_number

        for rejected in (
            "1. +919876543210",
            "+91 7977 396938 ext 4",
            "tel:+917977396938",
            "+917977396938, +919876543210",
            "<+917977396938>",
        ):
            self.assertEqual(clean_phone_number(rejected), "", rejected)

    def test_clean_phone_number_canonicalizes_to_one_e164_string(self):
        """Every spelling of one number must collapse to one string: it is both
        the TP OTP lookup key and the rate-limit bucket, so `91...` and `+91...`
        being distinct meant one number held two of each."""
        from telephony.twilio.sms import clean_phone_number

        canonical = "+917977396938"
        for spelling in (
            "+917977396938",
            "917977396938",
            "+91 7977 396938",
            "+91-7977-396938",
            "  +91 (7977) 396938  ",
            "++917977396938",
        ):
            self.assertEqual(clean_phone_number(spelling), canonical, spelling)

        # a bare "+" must come back empty so the "provide a valid phone number"
        # checks still fire, rather than handing Twilio a "+"
        for empty in ("", "   ", "+", "++", None):
            self.assertEqual(clean_phone_number(empty), "")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_otp_verifies_regardless_of_number_spelling(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The live consequence of the above: a code requested with one
        spelling has to verify with another."""
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        generate_otp(phone_number="+911234500004", purpose="Verification")

        result = verify_otp(
            phone_number="911234500004", otp="123456", purpose="Verification"
        )
        self.assertEqual(result, {"verified": True})

    @patch("telephony.twilio.sms.Twilio")
    def test_dispatch_sms_success_writes_redacted_sent_log(self, MockTwilio):
        """Exercises the real dispatch_sms, which every other test mocks out."""
        from telephony.twilio.sms import dispatch_sms

        client = MockTwilio.connect.return_value.twilio_client
        client.messages.create.return_value = frappe._dict(sid="SM_ok")

        log = dispatch_sms(PHONE_REDACT, "Your OTP is 123456.", purpose="OTP")

        self.assertEqual(log.status, "Sent")
        self.assertEqual(log.sid, "SM_ok")
        self.assertEqual(log.message, REDACTED_MESSAGE)

    @patch("telephony.twilio.sms.Twilio")
    def test_dispatch_sms_failure_is_generic_and_audited(self, MockTwilio):
        """The raised message must not carry Twilio internals, and the Failed
        row must still be written — via Redis, not via a commit. A commit here
        would also commit the *caller's* pending writes, so a Twilio outage
        would persist a calling doc hook's half-finished work."""
        from telephony.twilio.sms import dispatch_sms

        client = MockTwilio.connect.return_value.twilio_client
        client.messages.create.side_effect = Exception(
            "HTTP 401 error: ACfakeaccountsid https://api.twilio.com/2010-04-01"
        )

        with (
            patch("frappe.db.commit") as mock_commit,
            patch("telephony.twilio.sms.deferred_insert") as mock_deferred,
        ):
            with self.assertRaises(frappe.ValidationError) as ctx:
                dispatch_sms(PHONE_REDACT, "Your OTP is 123456.", purpose="OTP")
            mock_commit.assert_not_called()

        raised = str(ctx.exception)
        self.assertNotIn("ACfakeaccountsid", raised)
        self.assertNotIn("api.twilio.com", raised)

        doctype, records = mock_deferred.call_args[0]
        self.assertEqual(doctype, "TP SMS Log")
        (failed,) = records
        self.assertEqual(failed["status"], "Failed")
        self.assertEqual(failed["to"], PHONE_REDACT)
        # the queued payload must not carry the code either — it sits in Redis
        self.assertEqual(failed["message"], REDACTED_MESSAGE)
        self.assertNotIn("123456", str(failed))
        self.assertIn("ACfakeaccountsid", failed["error"])

    @patch("telephony.twilio.sms.Twilio")
    def test_dispatch_sms_failure_payload_survives_json(self, MockTwilio):
        """deferred_insert json.dumps() the record, so a datetime in it would
        raise TypeError and lose the audit row outright."""
        import json

        from telephony.twilio.sms import build_sms_log

        record = build_sms_log(
            PHONE_REDACT, TEST_SMS_FROM_NUMBER, "body", "OTP", "Failed", error="boom"
        )
        self.assertTrue(json.dumps([record]))

    @patch("telephony.twilio.sms.Twilio")
    def test_dispatch_sms_rejects_input_it_could_not_audit(self, MockTwilio):
        """`to` and `message` are mandatory on TP SMS Log, so an empty one made
        the failure path's own audit write raise MandatoryError — losing the
        Failed row and masking the real error. Reject before sending instead."""
        from telephony.twilio.sms import dispatch_sms

        client = MockTwilio.connect.return_value.twilio_client

        for to, message in (
            ("not-a-number", "Your OTP is 123456."),
            ("", "Your OTP is 123456."),
            (PHONE_REDACT, ""),
        ):
            with self.assertRaises(frappe.ValidationError):
                dispatch_sms(to, message, purpose="OTP")

        client.messages.create.assert_not_called()
        self.assertFalse(frappe.db.exists("TP SMS Log", {"to": ""}))

    def _drive_rate_limiter(self, path, cmd=None):
        """The limiter is inert without frappe.request, so give it one.

        `cmd` is left unset by default because that is the /api/v2 shape: only
        /api/v1 populates it, and rate_limit's cache key interpolates it.
        """
        from frappe.utils import set_request

        from telephony.otp import RATE_LIMIT_FIELD

        original_request = getattr(frappe.local, "request", None)
        self.addCleanup(setattr, frappe.local, "request", original_request)
        self.addCleanup(frappe.cache.delete_keys, "rl:")
        self.addCleanup(frappe.form_dict.pop, "cmd", None)
        self.addCleanup(frappe.form_dict.pop, "phone_number", None)
        self.addCleanup(frappe.form_dict.pop, RATE_LIMIT_FIELD, None)

        set_request(method="POST", path=path)
        frappe.local.request_ip = "127.0.0.1"
        if cmd:
            frappe.form_dict.cmd = cmd

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_rate_limit_actually_throttles_sends(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The limiter is inert without frappe.request, so the other tests never
        exercise it. Drive it with a request context and prove it fires."""
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        self._drive_rate_limiter("/api/method/telephony.twilio.sms.generate_otp")
        frappe.form_dict.phone_number = PHONE_NORMALIZE

        # limit is 5 per 10 minutes
        for _ in range(5):
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

        with self.assertRaises(frappe.RateLimitExceededError):
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_otp_rate_limit_is_per_recipient_not_per_ip_and_recipient(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """rate_limit defaults to ip_based=True, which makes the identity
        `ip:recipient` — so the cap documented as per-recipient was really
        per-(IP, recipient), and rotating IPs bought unlimited SMS to one number
        along with the Twilio bill for them."""
        from telephony.twilio.sms import generate_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        self._drive_rate_limiter("/api/method/telephony.twilio.sms.generate_otp")
        frappe.form_dict.phone_number = PHONE_NORMALIZE

        for i in range(5):
            frappe.local.request_ip = f"10.0.0.{i}"
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

        # a sixth IP must not get a sixth send to the same number
        frappe.local.request_ip = "10.0.0.99"
        with self.assertRaises(frappe.RateLimitExceededError):
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_generate_and_verify_do_not_share_a_rate_limit_counter(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """rate_limit's cache key is rl:{form_dict.cmd}:{identity}:{seconds} and
        only /api/v1 sets cmd. Over /api/v2 it renders as None, so generate and
        verify — same key, same identity, same 600s window — collided on one
        counter and four failed verifies blocked the next resend."""
        from telephony.twilio.sms import generate_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        # cmd deliberately unset: this is the /api/v2 shape
        self._drive_rate_limiter("/api/v2/method/telephony.twilio.sms.verify_otp")
        frappe.form_dict.phone_number = PHONE_NORMALIZE

        # burn most of verify's own budget (limit 10)
        for _ in range(8):
            self.assertEqual(
                verify_otp(
                    phone_number=PHONE_NORMALIZE, otp="000000", purpose="Verification"
                ),
                GENERIC_FAILURE,
            )

        # generate's budget (limit 5) must be untouched by them
        for _ in range(5):
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

        with self.assertRaises(frappe.RateLimitExceededError):
            generate_otp(phone_number=PHONE_NORMALIZE, purpose="Verification")

    @patch("telephony.twilio.sms.dispatch_sms")
    def test_send_sms_is_rate_limited_and_configurable(self, mock_dispatch_sms):
        """send_sms sends arbitrary content to arbitrary numbers at real cost,
        so it needs a cap — but a hardcoded one would break bulk senders, hence
        the setting."""
        from frappe.utils import set_request

        from telephony.twilio.sms import get_send_sms_limit, send_sms

        mock_dispatch_sms.side_effect = (
            lambda to, message, purpose="General": self._log_sent_sms(
                to, message, purpose
            )
        )

        original_request = getattr(frappe.local, "request", None)
        self.addCleanup(setattr, frappe.local, "request", original_request)
        self.addCleanup(frappe.cache.delete_keys, "rl:")

        set_request(method="POST", path="/api/method/telephony.twilio.sms.send_sms")
        frappe.local.request_ip = "127.0.0.1"
        frappe.form_dict.cmd = "telephony.twilio.sms.send_sms"
        self.addCleanup(frappe.form_dict.pop, "cmd", None)

        with self.change_settings(
            "TP OTP Settings", {"send_sms_rate_limit_per_hour": 2}
        ):
            frappe.clear_cache(doctype="TP OTP Settings")
            self.assertEqual(get_send_sms_limit(), 2)

            for _ in range(2):
                send_sms(to=PHONE_VERIFY, message="hi")

            with self.assertRaises(frappe.RateLimitExceededError):
                send_sms(to=PHONE_VERIFY, message="hi")

        # 0 means "no cap", for a trusted backend doing bulk sending
        with self.change_settings(
            "TP OTP Settings", {"send_sms_rate_limit_per_hour": 0}
        ):
            frappe.clear_cache(doctype="TP OTP Settings")
            self.assertGreater(get_send_sms_limit(), 1000)

    def test_send_sms_limit_does_not_fail_open_when_unconfigured(self):
        """A Single holds no value for a field until first save, so an existing
        site reads None here. That must not be read as "unlimited" — only an
        explicit 0 opts out."""
        from telephony.twilio.sms import DEFAULT_SEND_SMS_LIMIT, get_send_sms_limit

        with patch("frappe.get_cached_value", return_value=None):
            self.assertEqual(get_send_sms_limit(), DEFAULT_SEND_SMS_LIMIT)

        with patch("frappe.get_cached_value", return_value=0):
            self.assertGreater(get_send_sms_limit(), 1000)

        with patch("frappe.get_cached_value", return_value=25):
            self.assertEqual(get_send_sms_limit(), 25)

    def test_verify_pays_the_kdf_cost_on_every_failure_path(self):
        """The failure body is uniform; the latency has to be too, or a guest
        can time-probe which recipients have a live OTP."""
        from telephony import otp as otp_module

        recipient = PHONE_ATTEMPTS

        with patch.object(otp_module, "equalize_verify_cost") as mock_equalize:
            # no row at all
            otp_module.verify_otp_record(recipient, "SMS", "000000", "Login", 5)
            self.assertEqual(mock_equalize.call_count, 1)

            # a live row, but the attempt budget is already spent
            otp_module.create_otp_record(recipient, "SMS", "Login", "123456", 300, 5)
            frappe.db.set_value(
                "TP OTP",
                {"recipient": recipient, "is_verified": 0},
                "attempts",
                5,
            )
            otp_module.verify_otp_record(recipient, "SMS", "000000", "Login", 5)
            self.assertEqual(mock_equalize.call_count, 2)

            # an expired row
            frappe.db.set_value(
                "TP OTP",
                {"recipient": recipient, "is_verified": 0},
                {"attempts": 0, "expires_at": add_to_date(now_datetime(), seconds=-60)},
            )
            otp_module.verify_otp_record(recipient, "SMS", "000000", "Login", 5)
            self.assertEqual(mock_equalize.call_count, 3)

    def test_guest_may_call_otp_endpoints_but_not_send_sms(self):
        """Guest access is decided by frappe.is_whitelisted against the exact
        object registered at decoration time. Since normalize_form_field wraps
        the function *under* @frappe.whitelist, a mistake in that stacking would
        silently drop guest registration — so assert it directly."""
        from telephony import email_otp
        from telephony.twilio import sms

        guest_callable = [
            sms.generate_otp,
            sms.verify_otp,
            email_otp.generate_otp,
            email_otp.verify_otp,
        ]

        with self.set_user("Guest"):
            for fn in guest_callable:
                frappe.is_whitelisted(fn)  # must not raise

            with self.assertRaises(frappe.PermissionError):
                frappe.is_whitelisted(sms.send_sms)

        # POST-only: GET skips Frappe's CSRF check, so a state-changing
        # whitelisted method must not accept it.
        for fn in [*guest_callable, sms.send_sms]:
            self.assertEqual(
                tuple(frappe.allowed_http_methods_for_whitelisted_func[fn]), ("POST",)
            )

    def test_send_sms_requires_permission(self):
        from telephony.twilio.sms import send_sms

        with self.set_user("Guest"), self.assertRaises(frappe.PermissionError):
            send_sms(to=PHONE_VERIFY, message="hi")

    @patch("telephony.twilio.sms.dispatch_sms")
    def test_send_sms_allowed_for_permitted_user(self, mock_dispatch_sms):
        from telephony.twilio.sms import send_sms

        mock_dispatch_sms.side_effect = (
            lambda to, message, purpose="General": self._log_sent_sms(
                to, message, purpose
            )
        )

        result = send_sms(to=PHONE_VERIFY, message="hi")
        self.assertEqual(result["status"], "Sent")
