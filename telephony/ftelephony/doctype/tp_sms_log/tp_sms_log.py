# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document
from frappe.query_builder import Interval
from frappe.query_builder.functions import Now


class TPSMSLog(Document):
    @staticmethod
    def clear_old_logs(days=90):
        """Satisfies the LogType protocol that Log Settings checks for.

        `default_log_clearing_doctypes` in hooks.py is silently ignored unless
        the controller implements this, so registering a retention window is
        not enough on its own.
        """
        table = frappe.qb.DocType("TP SMS Log")
        frappe.db.delete(
            table, filters=(table.creation < (Now() - Interval(days=days)))
        )
