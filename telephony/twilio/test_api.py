from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import set_request
from frappe.utils.password import set_encrypted_password
from twilio.request_validator import RequestValidator

from telephony.twilio.api import (
    twilio_incoming_call_handler,
    update_call_status_info,
    update_recording_info,
    validate_twilio_request,
    voice,
)

AUTH_TOKEN = "test-auth-token"
HOST = "calls.example.com"
PATH = "/api/method/telephony.twilio.api.twilio_incoming_call_handler"
FORM = {
    "CallSid": "CAtestsignature",
    "Caller": "+15550000000",
    "From": "+15550000000",
    "To": "+15550000001",
    "CallStatus": "ringing",
}


class TestTwilioWebhookSignature(IntegrationTestCase):
    def setUp(self):
        frappe.db.savepoint("twilio_webhook_test")
        frappe.db.set_single_value(
            "TP Twilio Settings", {"enabled": 1, "account_sid": "ACtest"}
        )
        for field, value in {"auth_token": AUTH_TOKEN, "api_secret": "secret"}.items():
            set_encrypted_password(
                "TP Twilio Settings", "TP Twilio Settings", value, field
            )

    def tearDown(self):
        frappe.db.rollback(save_point="twilio_webhook_test")

    def test_accepts_request_signed_for_the_called_url(self):
        # The webhook points at a domain other than the site's host_name.
        self.make_request(sign_with=AUTH_TOKEN, query_string="source=console")
        with (
            patch.dict(frappe.local.conf, {"host_name": "https://site.example.com"}),
            patch.object(frappe.db, "commit"),
        ):
            twilio_incoming_call_handler(**FORM)
        self.assertTrue(frappe.db.exists("TP Call Log", FORM["CallSid"]))

    def test_rejects_unsigned_forged_or_tampered_request(self):
        for token, data in [
            (None, FORM),
            ("wrong-token", FORM),
            (AUTH_TOKEN, {**FORM, "From": "+15559999999"}),
        ]:
            self.make_request(sign_with=token, data=data)
            with self.assertRaises(frappe.PermissionError):
                twilio_incoming_call_handler(**data)
        self.assertFalse(frappe.db.exists("TP Call Log", FORM["CallSid"]))

    def test_every_webhook_rejects_unsigned_requests(self):
        webhooks = [
            voice,
            twilio_incoming_call_handler,
            update_recording_info,
            update_call_status_info,
        ]
        self.make_request()
        with (
            patch("telephony.twilio.api.Twilio") as twilio,
            patch("telephony.twilio.api.create_call_log") as create_call_log,
            patch("telephony.twilio.api.update_call_log") as update_call_log,
        ):
            for webhook in webhooks:
                with self.subTest(webhook=webhook.__name__):
                    with self.assertRaises(frappe.PermissionError):
                        webhook(**FORM)
        for mock in (twilio, create_call_log, update_call_log):
            self.assertFalse(mock.mock_calls)

    def test_rejects_when_twilio_is_disabled(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", 0)
        self.make_request(sign_with=AUTH_TOKEN)
        with self.assertRaises(frappe.PermissionError):
            validate_twilio_request()

    def make_request(self, sign_with=None, data=FORM, query_string=""):
        """Sets an HTTPS POST request behind a proxy, signed over FORM rather than `data`."""
        url = f"https://{HOST}{PATH}" + (f"?{query_string}" if query_string else "")
        signature = (
            RequestValidator(sign_with).compute_signature(url, FORM)
            if sign_with
            else ""
        )
        set_request(
            method="POST",
            base_url=f"http://{HOST}",
            path=PATH,
            query_string=query_string,
            data=data,
            headers={"X-Forwarded-Proto": "https", "X-Twilio-Signature": signature},
        )
