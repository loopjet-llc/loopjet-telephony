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
PHONE_OTHER = "+911234500008"
TEST_EMAIL = "test-otp@example.com"
TEST_EMAIL_OTHER = "other-otp@example.com"

TEST_RECIPIENTS = [
    PHONE_VERIFY,
    PHONE_ATTEMPTS,
    PHONE_EXPIRY,
    PHONE_BUDGET,
    PHONE_RESET,
    PHONE_NORMALIZE,
    PHONE_REDACT,
    PHONE_OTHER,
    TEST_EMAIL,
    TEST_EMAIL_OTHER,
]


class IntegrationTestTPOTP(IntegrationTestCase):
    """SMS and Email OTP flows end-to-end, with dispatch mocked out."""

    def setUp(self):
        super().setUp()

        # Stub only the live-Twilio check, so the rest of validate() still runs.
        patcher = patch.object(
            TPOTPSettings, "validate_sms_from_number", return_value=None
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        # Both reach the live Twilio API; stub them so change_settings works.
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

        # This counter lives in Redis, which outlives the transaction rollback.
        self.addCleanup(frappe.cache.delete_keys, "tp-otp-rl:")

        self.addCleanup(self._delete_test_records)

    def _delete_test_records(self):
        frappe.db.delete("TP OTP", {"recipient": ["in", TEST_RECIPIENTS]})
        frappe.db.delete("TP SMS Log", {"to": ["in", TEST_RECIPIENTS]})

    def _capture_bucket(self, seen, wrapped=None):
        """Read the bucket from inside the endpoint: call_channel_endpoint
        restores form_dict on the way out."""
        from telephony.otp import RATE_LIMIT_FIELD

        def side_effect(*args, **kwargs):
            seen.append(frappe.form_dict.get(RATE_LIMIT_FIELD))
            if wrapped:
                return wrapped(*args, **kwargs)

        return side_effect

    def _log_sent_sms(self, to, message, purpose="OTP"):
        """Stand in for dispatch_sms, but write a real TP SMS Log."""
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
        """The response goes to guests, so it must never echo the OTP."""
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
        """A resend must not hand out a new attempt budget while the previous
        OTP is still live."""
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

        # Refused outright: no SMS paid for, no row with a refreshed expiry.
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
        """A resend inside the lockout window must not push the expiry a full
        window further out, or retrying keeps the user locked out forever."""
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
        """The carry-forward must not become a permanent lockout."""
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
        """TP SMS Log is agent-readable and kept 90 days."""
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
        """rate_limit buckets on form_dict[key] verbatim, so the key has to be
        canonical or the cap is bypassable by reformatting."""
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
        """Uncanonicalizable recipients share one bucket, so varying the garbage
        cannot mint quota — but the key must not be left empty either."""
        from telephony.email_otp import clean_email
        from telephony.otp import (
            INVALID_RECIPIENT,
            RATE_LIMIT_FIELD,
            RATE_LIMIT_WINDOW,
            rate_limit_bucket,
        )

        self.addCleanup(frappe.form_dict.pop, "email", None)
        self.addCleanup(frappe.form_dict.pop, RATE_LIMIT_FIELD, None)

        # generous limit: this asserts the bucket key, not the cap.
        @rate_limit_bucket(
            "email", clean_email, "email:generate", 100, RATE_LIMIT_WINDOW
        )
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
        """The bucket must be the address that gets stored: otherwise
        "victim@x.com,," buckets apart but still delivers to victim@x.com."""
        from telephony.email_otp import clean_email
        from telephony.email_otp import generate_otp as generate_email_otp

        for spoofed in (f"{TEST_EMAIL},,", f"{TEST_EMAIL},,,,"):
            self.assertEqual(clean_email(spoofed), "")
            with self.assertRaises(frappe.ValidationError):
                generate_email_otp(email=spoofed, purpose="Verification")

        mock_dispatch_email.assert_not_called()

        # The invariant: for anything accepted, the bucket clean_email produces
        # has to be the recipient that gets stored.
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
        """Case variants must resolve to one recipient."""
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
        """validate_email_address() accepts a list and returns it re-joined,
        which would store two addresses as one recipient."""
        from telephony.email_otp import generate_otp as generate_email_otp

        with self.assertRaises(frappe.ValidationError):
            generate_email_otp(
                email=f"{TEST_EMAIL}, other@example.com", purpose="Verification"
            )

        mock_dispatch_email.assert_not_called()

    @patch("telephony.email_otp.dispatch_email_otp")
    def test_email_otp_rejects_newline_separated_addresses(self, mock_dispatch_email):
        """A newline is the separator that slips past a split_emails() count."""
        from telephony.email_otp import generate_otp as generate_email_otp

        for separator in ("\n", "\r"):
            with self.assertRaises(frappe.ValidationError):
                generate_email_otp(
                    email=f"{TEST_EMAIL}{separator}other@example.com",
                    purpose="Verification",
                )

        mock_dispatch_email.assert_not_called()

    def test_email_otp_is_redacted_from_the_email_queue(self):
        """Email Queue keeps the body for 30 days."""
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
        utf8mb4_unicode_ci then compares equal to their ASCII form."""
        from telephony.twilio.sms import clean_phone_number

        # fullwidth ９１ and Arabic-Indic ٩١ both pass str.isdigit()
        self.assertEqual(clean_phone_number("+９１1234500001"), "")
        self.assertEqual(clean_phone_number("+٩١1234500001"), "")
        self.assertEqual(clean_phone_number("+91 12345-00001"), "+911234500001")

    def test_clean_phone_number_rejects_rather_than_absorbing_stray_input(self):
        """Dropping unexpected characters rewrites one number into a different,
        deliverable one: "1. +919876543210" yielded +1919876543210."""
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
        the TP OTP lookup key and the rate-limit bucket."""
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

        # a bare "+" must come back empty, so the downstream checks still fire
        for empty in ("", "   ", "+", "++", None):
            self.assertEqual(clean_phone_number(empty), "")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_otp_verifies_regardless_of_number_spelling(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """A code requested with one spelling has to verify with another."""
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
        row must still be written — via Redis, not via a commit."""
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
        lose the audit row outright."""
        import json

        from telephony.twilio.sms import build_sms_log

        record = build_sms_log(
            PHONE_REDACT, TEST_SMS_FROM_NUMBER, "body", "OTP", "Failed", error="boom"
        )
        self.assertTrue(json.dumps([record]))

    @patch("telephony.twilio.sms.Twilio")
    def test_dispatch_sms_rejects_input_it_could_not_audit(self, MockTwilio):
        """Both are mandatory on TP SMS Log, so an empty one would make the
        failure path's own audit write raise and mask the real error."""
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
        """The limiter is inert without frappe.request, so give it one. `cmd`
        is unset by default because that is the /api/v2 shape."""
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
        """The limiter is inert without frappe.request; drive it with one."""
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
        `ip:recipient`, so rotating IPs buys unlimited SMS to one number."""
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
        """rate_limit's cache key interpolates cmd, which only /api/v1 sets, so
        over /api/v2 generate and verify collide on one counter."""
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
        """send_sms costs real money, so it needs a configurable cap."""
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
        """An unsaved Single reads None here, which must not mean "unlimited"."""
        from telephony.twilio.sms import DEFAULT_SEND_SMS_LIMIT, get_send_sms_limit

        with patch("frappe.get_cached_value", return_value=None):
            self.assertEqual(get_send_sms_limit(), DEFAULT_SEND_SMS_LIMIT)

        with patch("frappe.get_cached_value", return_value=0):
            self.assertGreater(get_send_sms_limit(), 1000)

        with patch("frappe.get_cached_value", return_value=25):
            self.assertEqual(get_send_sms_limit(), 25)

    def test_verify_pays_the_kdf_cost_on_every_failure_path(self):
        """The failure body is uniform; the latency has to be too."""
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
        """Guest access is decided against the exact object registered at
        decoration time, so a mistake in decorator stacking drops it silently."""
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

        # POST-only: GET skips Frappe's CSRF check.
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

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="777666")
    def test_send_and_verify_otp_resolve_the_channel(
        self, mock_generate_code, mock_dispatch_email
    ):
        """The entry point other apps use, reached with a channel name."""
        from telephony.otp import send_otp, verify_otp

        purpose = "Loan Lead LN-LEAD-00001"

        result = send_otp(TEST_EMAIL, "Email", purpose=purpose)
        self.assertEqual(set(result), {"sent", "expires_in"})
        mock_dispatch_email.assert_called_once()

        # the purpose scopes the code: another purpose must not match it
        self.assertEqual(
            verify_otp(TEST_EMAIL, "Email", "777666", purpose="Verification"),
            GENERIC_FAILURE,
        )
        self.assertEqual(
            verify_otp(TEST_EMAIL, "Email", "777666", purpose=purpose),
            {"verified": True},
        )

    def test_unknown_channel_is_rejected(self):
        """The channel names a module to import, so it is validated first."""
        from telephony.otp import send_otp, verify_otp

        for channel in ("Carrier Pigeon", "sms", "", None):
            with self.assertRaises(frappe.ValidationError):
                send_otp(TEST_EMAIL, channel)
            with self.assertRaises(frappe.ValidationError):
                verify_otp(TEST_EMAIL, channel, "777666")

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="777666")
    def test_send_otp_buckets_its_rate_limit_per_recipient(
        self, mock_generate_code, mock_dispatch_email
    ):
        """Without send_otp publishing the recipient into form_dict, every
        recipient shares one site-wide cap."""
        from telephony.otp import send_otp

        seen = []
        mock_dispatch_email.side_effect = self._capture_bucket(seen)

        self._drive_rate_limiter("/api/method/telephony.otp.send_otp")

        # limit is 5 per 10 minutes, per recipient
        for _ in range(5):
            send_otp(TEST_EMAIL, "Email")

        self.assertEqual(seen[-1], f"email:generate:{TEST_EMAIL}")

        with self.assertRaises(frappe.RateLimitExceededError):
            send_otp(TEST_EMAIL, "Email")

        # a different recipient keeps a budget of their own
        send_otp(TEST_EMAIL_OTHER, "Email")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_send_and_verify_otp_resolve_the_sms_channel(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """The SMS half of the registry: the recipient reaches the endpoint
        under the field name OTP_CHANNELS claims it takes."""
        from telephony.otp import send_otp, verify_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms
        purpose = "Loan Lead LN-LEAD-00001"

        result = send_otp(PHONE_VERIFY, "SMS", purpose=purpose)
        self.assertEqual(set(result), {"sent", "expires_in"})
        mock_dispatch_sms.assert_called_once()
        self.assertEqual(mock_dispatch_sms.call_args.args[0], PHONE_VERIFY)

        self.assertEqual(
            verify_otp(PHONE_VERIFY, "SMS", "123456", purpose="Verification"),
            GENERIC_FAILURE,
        )
        self.assertEqual(
            verify_otp(PHONE_VERIFY, "SMS", "123456", purpose=purpose),
            {"verified": True},
        )

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_send_otp_buckets_its_rate_limit_per_recipient_over_sms(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """Same per-recipient bucketing as the email case, on the channel whose
        recipient field differs from it."""
        from telephony.otp import send_otp

        seen = []
        mock_dispatch_sms.side_effect = self._capture_bucket(seen, self._log_sent_sms)

        self._drive_rate_limiter("/api/method/telephony.otp.send_otp")

        # limit is 5 per 10 minutes, per recipient
        for _ in range(5):
            send_otp(PHONE_VERIFY, "SMS")

        self.assertEqual(seen[-1], f"sms:generate:{PHONE_VERIFY}")

        with self.assertRaises(frappe.RateLimitExceededError):
            send_otp(PHONE_VERIFY, "SMS")

        # a different recipient keeps a budget of their own
        send_otp(PHONE_OTHER, "SMS")

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="777666")
    def test_send_otp_leaves_form_dict_as_it_found_it(
        self, mock_generate_code, mock_dispatch_email
    ):
        """Left behind, the recipient is PII that frappe writes into Error Log
        metadata on any later unhandled exception in the same request."""
        from telephony.otp import RATE_LIMIT_FIELD, send_otp

        self.addCleanup(frappe.form_dict.pop, "email", None)
        self.addCleanup(frappe.form_dict.pop, RATE_LIMIT_FIELD, None)

        # a caller with an 'email' parameter of its own must get it back intact
        frappe.form_dict.email = "caller-value"
        send_otp(TEST_EMAIL, "Email")
        self.assertEqual(frappe.form_dict.email, "caller-value")

        # and one that never had the key must not acquire it
        frappe.form_dict.pop("email", None)
        frappe.form_dict.pop(RATE_LIMIT_FIELD, None)
        send_otp(TEST_EMAIL_OTHER, "Email")
        self.assertNotIn("email", frappe.form_dict)
        self.assertNotIn(RATE_LIMIT_FIELD, frappe.form_dict)

    @patch("telephony.email_otp.dispatch_email_otp")
    @patch("telephony.email_otp.generate_otp_code", return_value="777666")
    def test_send_otp_is_rate_limited_without_a_request(
        self, mock_generate_code, mock_dispatch_email
    ):
        """frappe's @rate_limit returns early when frappe.request is None, so on
        a background job the cap is not merely wrong but absent."""
        from telephony.otp import send_otp

        # an unbound LocalProxy here, not None — falsy either way
        self.assertFalse(frappe.request, "this test must run off the request path")

        for _ in range(5):
            send_otp(TEST_EMAIL, "Email")

        with self.assertRaises(frappe.RateLimitExceededError):
            send_otp(TEST_EMAIL, "Email")

        # still bucketed per recipient, not one shared counter
        send_otp(TEST_EMAIL_OTHER, "Email")

    @patch("telephony.twilio.sms.dispatch_sms")
    @patch("telephony.twilio.sms.generate_otp_code", return_value="123456")
    def test_non_string_recipient_is_rejected_by_type_not_by_crash(
        self, mock_generate_code, mock_dispatch_sms
    ):
        """A mistyped recipient must fail as a type error, not as an
        AttributeError from inside the rate-limit decorator."""
        from telephony.otp import send_otp

        mock_dispatch_sms.side_effect = self._log_sent_sms

        with self.assertRaises(frappe.exceptions.FrappeTypeError):
            send_otp(911234500001, "SMS")

        mock_dispatch_sms.assert_not_called()
