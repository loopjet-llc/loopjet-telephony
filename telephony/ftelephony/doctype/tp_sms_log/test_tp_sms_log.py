# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# See license.txt

import frappe
from frappe.tests import IntegrationTestCase

EXTRA_TEST_RECORD_DEPENDENCIES = []
IGNORE_TEST_RECORD_DEPENDENCIES = []


class IntegrationTestTPSMSLog(IntegrationTestCase):
    """Integration tests for TP SMS Log."""

    def test_create_sms_log_defaults(self):
        doc = frappe.get_doc(
            {
                "doctype": "TP SMS Log",
                "to": "+911234500009",
                "from": "+15005550006",
                "message": "Test message",
            }
        )
        doc.insert(ignore_permissions=True)
        self.addCleanup(
            lambda: frappe.delete_doc(
                "TP SMS Log", doc.name, force=True, ignore_permissions=True
            )
        )

        reloaded = frappe.get_doc("TP SMS Log", doc.name)
        self.assertEqual(reloaded.status, "Queued")
        self.assertEqual(reloaded.purpose, "General")
        self.assertEqual(reloaded.to, "+911234500009")

    def test_sent_by_defaults_to_current_user_when_not_guest(self):
        doc = frappe.get_doc(
            {
                "doctype": "TP SMS Log",
                "to": "+911234500009",
                "from": "+15005550006",
                "message": "Test message",
                "status": "Sent",
                "sent_by": frappe.session.user,
            }
        )
        doc.insert(ignore_permissions=True)
        self.addCleanup(
            lambda: frappe.delete_doc(
                "TP SMS Log", doc.name, force=True, ignore_permissions=True
            )
        )

        reloaded = frappe.get_doc("TP SMS Log", doc.name)
        self.assertEqual(reloaded.sent_by, frappe.session.user)
