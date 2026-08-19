import frappe
from frappe import _
from frappe.deferred_insert import deferred_insert
from frappe.rate_limiter import rate_limit
from frappe.utils import now

from telephony.otp import (
    GENERATE_LIMIT,
    RATE_LIMIT_FIELD,
    RATE_LIMIT_WINDOW,
    VERIFY_LIMIT,
    clean_purpose,
    create_otp_record,
    generate_otp_code,
    rate_limit_bucket,
    verify_otp_record,
)

from .twilio_handler import Twilio

# TP SMS Log is agent-readable and kept 90 days, so the OTP body is dropped
# and only the routing metadata is logged.
REDACTED_MESSAGE = "[redacted]"

ASCII_DIGITS = frozenset("0123456789")

# Anything outside this and ASCII_DIGITS is a rejection, not something to
# clean up.
PHONE_SEPARATORS = frozenset(" -().")

# Stand-in for "no cap" when send_sms_rate_limit_per_hour is explicitly 0.
UNLIMITED_SENDS = 10**9

# Mirrors the field default, for sites whose settings have never been saved.
DEFAULT_SEND_SMS_LIMIT = 60


def clean_phone_number(phone_number: str) -> str:
    """Canonicalize to one E.164-shaped string, since this is both the
    ``TP OTP.recipient`` key and the rate-limit bucket. Unexpected characters
    are rejected, never stripped: dropping them rewrites one number into
    another, deliverable one. No country code is inferred."""
    digits = []
    for char in (phone_number or "").strip().lstrip("+"):
        if char in ASCII_DIGITS:
            digits.append(char)
        elif char not in PHONE_SEPARATORS:
            return ""

    # "" rather than a bare "+", so the emptiness checks downstream still fire.
    return f"+{''.join(digits)}" if digits else ""


def get_sms_settings():
    settings = frappe.get_cached_doc("TP OTP Settings")
    if not settings.enabled:
        frappe.throw(_("Please enable SMS in TP OTP Settings to send SMS."))
    return settings


def build_sms_log(to, from_number, message, purpose, status, sid=None, error=None):
    """Build the TP SMS Log payload, with the body redacted for OTP traffic.
    ``sent_at`` is a string, not a datetime: this dict has to survive
    ``json.dumps`` on the deferred path."""
    return {
        "doctype": "TP SMS Log",
        "to": to,
        "from": from_number,
        "message": REDACTED_MESSAGE if purpose == "OTP" else message,
        "purpose": purpose,
        "status": status,
        "sid": sid,
        "error": error,
        "sent_by": frappe.session.user if frappe.session.user != "Guest" else None,
        "sent_at": now(),
    }


def create_sms_log(to, from_number, message, purpose, status, sid=None, error=None):
    log = frappe.get_doc(
        build_sms_log(to, from_number, message, purpose, status, sid=sid, error=error)
    )
    log.insert(ignore_permissions=True)
    return log


def dispatch_sms(to, message, purpose="General"):
    """Send an SMS via Twilio and log the result."""
    settings = get_sms_settings()

    to = clean_phone_number(to)
    # Both are mandatory on TP SMS Log, so an empty one would make the failure
    # path's own audit write fail and mask the real error. Reject up front.
    if not to:
        frappe.throw(_("Please provide a valid phone number."))
    if not message:
        frappe.throw(_("Cannot send an empty SMS."))

    # NOTE: two KDF rounds plus an uncached query per SMS, inside connect().
    twilio = Twilio.connect()
    if not twilio:
        frappe.throw(_("Please enable and configure TP Twilio Settings to send SMS."))

    from_number = settings.sms_from_number

    try:
        message_obj = twilio.twilio_client.messages.create(
            to=to, from_=from_number, body=message
        )
    except Exception as e:
        # Deferred, not committed: the Failed row must outlive the throw below,
        # but a commit here would also persist the caller's pending writes.
        deferred_insert(
            "TP SMS Log",
            [build_sms_log(to, from_number, message, purpose, "Failed", error=str(e))],
        )
        # Explicit message: without one, log_error renders every frame's locals
        # into Error Log — the OTP body and the decrypted api_secret included.
        frappe.log_error(
            title="Failed to send SMS via Twilio",
            message=f"to={to} error={type(e).__name__}: {e}",
            defer_insert=True,
        )
        # The raw Twilio error carries account SIDs and the from-number, and
        # generate_otp is guest-callable.
        frappe.throw(_("Could not send the SMS. Please try again later."))

    return create_sms_log(
        to, from_number, message, purpose, "Sent", sid=message_obj.sid
    )


def get_send_sms_limit():
    """Per-hour cap for send_sms, read at request time. 0 means no limit."""
    limit = frappe.get_cached_value(
        "TP OTP Settings", "TP OTP Settings", "send_sms_rate_limit_per_hour"
    )

    # None is not 0: a Single holds no value until first saved, and treating
    # that as "unlimited" would leave every such site uncapped.
    if limit is None:
        return DEFAULT_SEND_SMS_LIMIT

    # The limiter has no "unlimited", so use an unreachable ceiling.
    return limit or UNLIMITED_SENDS


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=get_send_sms_limit, seconds=60 * 60)
def send_sms(to: str, message: str):
    """Send a plain SMS. Rate limited per client rather than per recipient:
    the risk here is total spend, not hammering of one number."""
    # Defer to the DocType's permissions so the role set stays configurable.
    frappe.has_permission("TP SMS Log", "create", throw=True)

    log = dispatch_sms(to, message, purpose="General")
    return {"name": log.name, "status": log.status}


# ip_based=False: the default mixes in the client IP, so rotating IPs would
# buy unlimited SMS to a single number.
@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@rate_limit_bucket(
    "phone_number",
    clean_phone_number,
    "sms:generate",
    GENERATE_LIMIT,
    RATE_LIMIT_WINDOW,
)
@rate_limit(
    key=RATE_LIMIT_FIELD,
    limit=GENERATE_LIMIT,
    seconds=RATE_LIMIT_WINDOW,
    ip_based=False,
)
def generate_otp(phone_number: str, purpose: str = "Verification"):
    """Generate an OTP and send it over SMS to the given phone number."""
    settings = get_sms_settings()
    phone_number = clean_phone_number(phone_number)
    if not phone_number:
        frappe.throw(_("Please provide a valid phone number."))

    purpose = clean_purpose(purpose)
    otp = generate_otp_code(settings.otp_length)
    expiry_seconds = settings.otp_expiry_in_seconds

    message = settings.otp_message_template.format(
        otp=otp, expiry_minutes=max(1, expiry_seconds // 60)
    )

    # Record first, so a user can never hold a code with no record to verify
    # against; a send failure rolls this back with the rest of the request.
    otp_doc = create_otp_record(
        phone_number,
        "SMS",
        purpose,
        otp,
        expiry_seconds,
        settings.otp_max_attempts,
    )
    log = dispatch_sms(phone_number, message, purpose="OTP")
    otp_doc.db_set("notification_log", log.name, update_modified=False)

    return {"sent": True, "expires_in": expiry_seconds}


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@rate_limit_bucket(
    "phone_number", clean_phone_number, "sms:verify", VERIFY_LIMIT, RATE_LIMIT_WINDOW
)
@rate_limit(
    key=RATE_LIMIT_FIELD, limit=VERIFY_LIMIT, seconds=RATE_LIMIT_WINDOW, ip_based=False
)
def verify_otp(phone_number: str, otp: str, purpose: str = "Verification"):
    """Verify an OTP previously sent to the given phone number."""
    settings = get_sms_settings()
    phone_number = clean_phone_number(phone_number)
    if not phone_number:
        frappe.throw(_("Please provide a valid phone number."))

    return verify_otp_record(
        phone_number, "SMS", otp, clean_purpose(purpose), settings.otp_max_attempts
    )
