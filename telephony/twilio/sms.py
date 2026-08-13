import frappe
from frappe import _
from frappe.deferred_insert import deferred_insert
from frappe.rate_limiter import rate_limit
from frappe.utils import now

from telephony.otp import (
    RATE_LIMIT_FIELD,
    clean_purpose,
    create_otp_record,
    generate_otp_code,
    rate_limit_bucket,
    verify_otp_record,
)

from .twilio_handler import Twilio

# TP SMS Log is readable by TP Agent and retained for 90 days, so writing the
# rendered OTP body there would undo hashing the code in TP OTP. Keep the
# routing metadata (to/from/sid/status) and drop the body.
REDACTED_MESSAGE = "[redacted]"

ASCII_DIGITS = frozenset("0123456789")

# Punctuation people actually type into phone numbers. Anything outside this and
# ASCII_DIGITS makes the input a rejection rather than something to clean up.
PHONE_SEPARATORS = frozenset(" -().")

# Stand-in for "no cap" when send_sms_rate_limit_per_hour is explicitly 0.
UNLIMITED_SENDS = 10**9

# Mirrors the field default, for sites whose settings have never been saved.
DEFAULT_SEND_SMS_LIMIT = 60


def clean_phone_number(phone_number: str) -> str:
    """Canonicalize to a single E.164-shaped string: ``+`` then ASCII digits.

    Every spelling of one number has to collapse to one string, because this
    value is both the ``TP OTP.recipient`` lookup key and the rate-limit
    bucket. Keeping the caller's ``+`` verbatim was not enough: ``91…`` and
    ``+91…`` stayed distinct, so one number still had two OTP rows and two
    quotas. Digits are extracted and a single ``+`` is re-attached, so all of
    ``+91 79-7739 6938``, ``917977396938`` and ``+917977396938`` agree.

    Anything that is not a digit or ordinary phone punctuation is a *rejection*,
    not something to strip. Discarding unexpected characters silently turns one
    number into a different, deliverable one: ``"1. +919876543210"`` used to
    yield ``+1919876543210``, a live US number, so the OTP went to a stranger.
    Non-ASCII digits are rejected for the same reason and one more — they are
    true under ``str.isdigit()``, and MariaDB's default ``utf8mb4_unicode_ci``
    collation compares them equal to their ASCII form, so keeping them would let
    a caller land on another recipient's row while holding a bucket of their own.

    Leading ``+`` signs are the one thing dropped rather than rejected, so a
    doubled ``++91…`` typo still resolves instead of failing a verification the
    user has no way to diagnose.

    No country code is inferred: telephony is a library and the caller's
    dialling context is unknown, so a national-format number stays national
    and Twilio rejects it, exactly as before.
    """
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

    Shared by both dispatch paths so the redaction cannot drift between them:
    the failure path routes its row through Redis, and the rendered code must
    not be sitting in a queue payload either.

    ``sent_at`` is a string, not a datetime — this dict has to survive
    ``json.dumps`` on the deferred path.
    """
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
    # `to` and `message` are both mandatory on TP SMS Log, so an empty one would
    # make the failure path's *own* audit write fail — losing the Failed row and
    # masking the real error behind a MandatoryError. Reject up front, where
    # there is still a caller to tell and no credential has been decrypted yet.
    if not to:
        frappe.throw(_("Please provide a valid phone number."))
    if not message:
        frappe.throw(_("Cannot send an empty SMS."))

    # NOTE: connect() reads TP Twilio Settings from cache, but Twilio.__init__
    # still decrypts api_secret and get_twilio_client() re-fetches the Single
    # uncached to decrypt auth_token — two KDF rounds plus a query per SMS.
    twilio = Twilio.connect()
    if not twilio:
        frappe.throw(_("Please enable and configure TP Twilio Settings to send SMS."))

    from_number = settings.sms_from_number

    try:
        message_obj = twilio.twilio_client.messages.create(
            to=to, from_=from_number, body=message
        )
    except Exception as e:
        # Deferred through Redis, not committed. The Failed row is this attempt's
        # audit trail and has to outlive the frappe.throw below, but a
        # frappe.db.commit() here would also commit whatever the *caller* had
        # pending: called from a doc hook, an unrelated Twilio outage would
        # persist that hook's half-finished writes while the request aborted.
        # deferred_insert parks the row in Redis and the scheduler inserts it in
        # a transaction of its own, so neither side can drag the other along.
        deferred_insert(
            "TP SMS Log",
            [build_sms_log(to, from_number, message, purpose, "Failed", error=str(e))],
        )
        # Pass an explicit message: with none, log_error falls back to
        # get_traceback(with_context=True), which renders every frame's locals
        # into Error Log — including `message`, the rendered OTP body, and the
        # decrypted api_secret held by twilio's own client frames. That would
        # leak in cleartext exactly what is redacted and encrypted elsewhere.
        # Deferred for the same reason as the row above.
        frappe.log_error(
            title="Failed to send SMS via Twilio",
            message=f"to={to} error={type(e).__name__}: {e}",
            defer_insert=True,
        )
        # The raw Twilio error carries account SIDs, the configured from-number
        # and endpoint URLs; generate_otp is guest-callable, so keep it out.
        frappe.throw(_("Could not send the SMS. Please try again later."))

    return create_sms_log(
        to, from_number, message, purpose, "Sent", sid=message_obj.sid
    )


def get_send_sms_limit():
    """Per-hour cap for send_sms, read at request time.

    A hardcoded number would either be too low for a site doing bulk
    notifications or too high to protect the Twilio balance of one that isn't,
    so this is configurable, with 0 meaning no limit. ``rate_limit`` accepts a
    callable for exactly this.
    """
    limit = frappe.get_cached_value(
        "TP OTP Settings", "TP OTP Settings", "send_sms_rate_limit_per_hour"
    )

    # None is not 0. A Single holds no value for a field until the doc is first
    # saved, so on an existing site this reads None until someone opens the
    # form — treating that as "unlimited" would silently leave every such site
    # uncapped. Only an explicit 0 opts out.
    if limit is None:
        return DEFAULT_SEND_SMS_LIMIT

    # The limiter has no "unlimited", so use a ceiling no single client will
    # reach within one window.
    return limit or UNLIMITED_SENDS


@frappe.whitelist(methods=["POST"])
@rate_limit(limit=get_send_sms_limit, seconds=60 * 60)
def send_sms(to: str, message: str):
    """Send a plain SMS. Restricted to telephony agents/managers.

    Unlike the OTP endpoints this is rate limited per client rather than per
    recipient: the risk here is total spend on arbitrary numbers, not repeated
    hammering of one number.
    """
    # Defer to the DocType's permissions so the role set stays configurable.
    frappe.has_permission("TP SMS Log", "create", throw=True)

    log = dispatch_sms(to, message, purpose="General")
    return {"name": log.name, "status": log.status}


# ip_based=False: the default mixes the client IP into the identity, making this
# a per-(IP, recipient) cap rather than the per-recipient one it is documented
# as. Rotating IPs would then buy unlimited SMS to a single number, and the
# Twilio bill with it.
@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@rate_limit_bucket("phone_number", clean_phone_number, "sms:generate")
@rate_limit(key=RATE_LIMIT_FIELD, limit=5, seconds=10 * 60, ip_based=False)
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
    # against. The failure path in dispatch_sms no longer commits, so a send
    # failure rolls this record back with the rest of the request.
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
@rate_limit_bucket("phone_number", clean_phone_number, "sms:verify")
@rate_limit(key=RATE_LIMIT_FIELD, limit=10, seconds=10 * 60, ip_based=False)
def verify_otp(phone_number: str, otp: str, purpose: str = "Verification"):
    """Verify an OTP previously sent to the given phone number."""
    settings = get_sms_settings()
    phone_number = clean_phone_number(phone_number)
    if not phone_number:
        frappe.throw(_("Please provide a valid phone number."))

    return verify_otp_record(
        phone_number, "SMS", otp, clean_purpose(purpose), settings.otp_max_attempts
    )
