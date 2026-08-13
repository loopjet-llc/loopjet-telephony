# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# See license.txt

from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase

EXTRA_TEST_RECORD_DEPENDENCIES = []
IGNORE_TEST_RECORD_DEPENDENCIES = []

TEST_FROM_NUMBER = "+15005550006"


class IntegrationTestTPOTPSettings(IntegrationTestCase):
    """Integration tests for TP OTP Settings."""

    def setUp(self):
        super().setUp()
        self._original_twilio_enabled = frappe.db.get_single_value(
            "TP Twilio Settings", "enabled"
        )
        self._original_settings = frappe.get_doc("TP OTP Settings").as_dict()
        self.addCleanup(self._restore_settings)

    def _restore_settings(self):
        # set_single_value deliberately bypasses validate() so a test that left
        # a deliberately-invalid value behind can still be rolled back.
        original = self._original_settings
        frappe.db.set_single_value(
            "TP Twilio Settings", "enabled", self._original_twilio_enabled
        )
        frappe.db.set_single_value(
            "TP OTP Settings",
            {
                "enabled": original.get("enabled"),
                "enable_email_otp": original.get("enable_email_otp"),
                "sms_from_number": original.get("sms_from_number"),
                "otp_length": original.get("otp_length"),
                "otp_expiry_in_seconds": original.get("otp_expiry_in_seconds"),
                "otp_max_attempts": original.get("otp_max_attempts"),
                "otp_message_template": original.get("otp_message_template"),
                "email_otp_subject": original.get("email_otp_subject"),
            },
        )
        frappe.clear_cache(doctype="TP Twilio Settings")
        frappe.clear_cache(doctype="TP OTP Settings")

    def _set_twilio_enabled(self, enabled):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", enabled)
        frappe.clear_cache(doctype="TP Twilio Settings")

    def test_throws_when_twilio_not_enabled(self):
        self._set_twilio_enabled(0)

        doc = frappe.get_doc("TP OTP Settings")
        doc.enabled = 1
        doc.sms_from_number = TEST_FROM_NUMBER
        with self.assertRaises(frappe.ValidationError):
            doc.save(ignore_permissions=True)

    def test_throws_when_number_not_on_twilio_account(self):
        self._set_twilio_enabled(1)

        with patch("telephony.twilio.twilio_handler.Twilio") as MockTwilio:
            MockTwilio.return_value.get_phone_numbers.return_value = ["+10000000000"]

            doc = frappe.get_doc("TP OTP Settings")
            doc.enabled = 1
            doc.sms_from_number = TEST_FROM_NUMBER
            with self.assertRaises(frappe.ValidationError):
                doc.save(ignore_permissions=True)

    def test_saves_when_number_matches_twilio_account(self):
        self._set_twilio_enabled(1)

        with patch("telephony.twilio.twilio_handler.Twilio") as MockTwilio:
            MockTwilio.return_value.get_phone_numbers.return_value = [TEST_FROM_NUMBER]

            doc = frappe.get_doc("TP OTP Settings")
            doc.enabled = 1
            doc.sms_from_number = TEST_FROM_NUMBER
            doc.save(ignore_permissions=True)

        self.assertEqual(frappe.db.get_single_value("TP OTP Settings", "enabled"), 1)

    def test_enable_email_otp_does_not_require_twilio(self):
        self._set_twilio_enabled(0)

        doc = frappe.get_doc("TP OTP Settings")
        doc.enabled = 0
        doc.enable_email_otp = 1
        # should not throw, Email OTP has no Twilio dependency
        doc.save(ignore_permissions=True)

        self.assertEqual(
            frappe.db.get_single_value("TP OTP Settings", "enable_email_otp"), 1
        )

    def test_unreachable_twilio_gives_a_message_not_a_traceback(self):
        """Constructing Twilio() is itself a live step — it decrypts api_secret
        and builds a TwilioClient — so it has to be inside the try. Outside it, a
        blank credential wedged the form with a raw traceback, which is exactly
        the failure the handler was added to prevent."""
        self._set_twilio_enabled(1)

        with patch("telephony.twilio.twilio_handler.Twilio") as MockTwilio:
            MockTwilio.side_effect = Exception("Credential is blank")

            doc = frappe.get_doc("TP OTP Settings")
            doc.enabled = 1
            doc.sms_from_number = TEST_FROM_NUMBER
            with self.assertRaises(frappe.ValidationError) as ctx:
                doc.save(ignore_permissions=True)

        self.assertIn("Could not reach Twilio", str(ctx.exception))

    def test_twilio_failure_is_logged_without_a_traceback_of_locals(self):
        """log_error with no message falls back to get_traceback(with_context=True),
        which renders every frame's locals — and twilio's own client frames hold
        the decrypted api_secret, so the credential lands in Error Log."""
        self._set_twilio_enabled(1)

        with (
            patch("telephony.twilio.twilio_handler.Twilio") as MockTwilio,
            patch("frappe.log_error") as mock_log_error,
        ):
            MockTwilio.return_value.get_phone_numbers.side_effect = Exception(
                "HTTP 401 error: authenticate"
            )

            doc = frappe.get_doc("TP OTP Settings")
            doc.enabled = 1
            doc.sms_from_number = TEST_FROM_NUMBER
            with self.assertRaises(frappe.ValidationError):
                doc.save(ignore_permissions=True)

        _, kwargs = mock_log_error.call_args
        self.assertTrue(kwargs.get("message"))
        self.assertIn("HTTP 401 error", kwargs["message"])

    def test_rejects_otp_length_below_minimum(self):
        """A 1-digit OTP is 10 combinations; no attempt cap makes that safe."""
        doc = frappe.get_doc("TP OTP Settings")
        doc.enabled = 0
        doc.otp_length = 1
        with self.assertRaises(frappe.ValidationError):
            doc.save(ignore_permissions=True)

    def test_rejects_non_positive_expiry(self):
        doc = frappe.get_doc("TP OTP Settings")
        doc.enabled = 0
        doc.otp_expiry_in_seconds = 0
        with self.assertRaises(frappe.ValidationError):
            doc.save(ignore_permissions=True)

    def test_rejects_non_positive_max_attempts(self):
        doc = frappe.get_doc("TP OTP Settings")
        doc.enabled = 0
        doc.otp_max_attempts = 0
        with self.assertRaises(frappe.ValidationError):
            doc.save(ignore_permissions=True)

    def test_null_otp_params_give_a_message_not_a_traceback(self):
        """A NULL left by db.set_single_value or a patch must not make
        `None < 4` raise TypeError and wedge the settings form."""
        for field in ("otp_length", "otp_expiry_in_seconds", "otp_max_attempts"):
            doc = frappe.get_doc("TP OTP Settings")
            doc.enabled = 0
            setattr(doc, field, None)
            with self.assertRaises(frappe.ValidationError):
                doc.save(ignore_permissions=True)

    def test_rejects_template_without_otp_placeholder(self):
        """Without {otp} the recipient would receive a message with no code."""
        doc = frappe.get_doc("TP OTP Settings")
        doc.enabled = 0
        doc.otp_message_template = "Your code is ready."
        with self.assertRaises(frappe.ValidationError):
            doc.save(ignore_permissions=True)
