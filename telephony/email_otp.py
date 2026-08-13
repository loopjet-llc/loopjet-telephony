from email.utils import parseaddr

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit
from frappe.utils import split_emails, validate_email_address

from telephony.otp import (
    RATE_LIMIT_FIELD,
    clean_purpose,
    create_otp_record,
    generate_otp_code,
    rate_limit_bucket,
    verify_otp_record,
)


def clean_email(email: str) -> str:
    """Canonicalize for rate-limit bucketing.

    Must agree with what ``validate_single_email`` ultimately stores, or the
    quota can be split across spellings of one address. So collapse the
    separators frappe treats as separators, and reduce ``Foo <a@x.com>`` to the
    bare address. This runs ahead of validation and on unvalidated input, so it
    never throws — rejection is ``validate_single_email``'s job.

    Unparseable input yields ``""``, never the raw string. Falling back to the
    raw string is what made the bucket disagree with the recipient that gets
    stored: ``parseaddr`` bails to ``("", "")`` on malformed input, so
    ``victim@x.com,,`` bucketed on ``"victim@x.com,,"`` while
    ``validate_email_address``'s per-piece fallback still resolved it to
    ``victim@x.com`` — and every extra comma minted another untouched 5-per-10
    minutes against the same inbox.
    """
    email = (email or "").replace("\n", ",").replace("\r", ",").strip().lower()
    return parseaddr(email)[1]


def validate_single_email(email: str) -> str:
    """Require exactly one address.

    ``frappe.utils.validate_email_address`` parses with ``getaddresses()`` and
    returns the addresses re-joined, so ``"a@x.com, b@y.com"`` passes. That
    would land two addresses in a single ``TP OTP.recipient`` and produce a
    malformed ``To:`` header, since ``sendmail`` does not re-split a list item.

    The count has to be taken from what ``validate_email_address`` *returns*,
    not from ``split_emails`` of the input: ``split_emails`` collapses ``\\n``
    to a space before splitting, while ``validate_email_address`` turns it into
    a separator. Checking the input therefore lets ``"a@x.com\\nb@y.com"``
    through as "one" address and yields two.
    """
    email = clean_email(email)
    if not email:
        frappe.throw(_("Please provide a valid email address."))

    validated = validate_email_address(email, throw=True)
    if len(split_emails(validated.replace("\n", ",").replace("\r", ","))) != 1:
        frappe.throw(_("Please provide a single email address."))

    return validated


def get_email_otp_settings():
    settings = frappe.get_cached_doc("TP OTP Settings")
    if not settings.enable_email_otp:
        frappe.throw(_("Please enable Email OTP in TP OTP Settings."))
    return settings


def dispatch_email_otp(email, message, subject):
    # redact_message_after_send: the queued body carries the cleartext code and
    # Email Queue is retained for 30 days, so without this the OTP outlives its
    # own expiry in a readable table — undoing the hashing in TP OTP, the same
    # way an unredacted TP SMS Log would on the SMS side.
    frappe.sendmail(
        recipients=[email],
        subject=subject,
        message=message,
        redact_message_after_send=True,
    )


# ip_based=False: the default mixes the client IP into the identity, making this
# a per-(IP, recipient) cap rather than the per-recipient one it is documented
# as. Rotating IPs would then buy unlimited mail to a single inbox.
@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@rate_limit_bucket("email", clean_email, "email:generate")
@rate_limit(key=RATE_LIMIT_FIELD, limit=5, seconds=10 * 60, ip_based=False)
def generate_otp(email: str, purpose: str = "Verification"):
    """Generate an OTP and send it over email to the given address."""
    settings = get_email_otp_settings()
    email = validate_single_email(email)

    purpose = clean_purpose(purpose)
    otp = generate_otp_code(settings.otp_length)
    expiry_seconds = settings.otp_expiry_in_seconds

    message = settings.otp_message_template.format(
        otp=otp, expiry_minutes=max(1, expiry_seconds // 60)
    )
    subject = settings.email_otp_subject

    # Record first, mirroring the SMS flow: the mail is queued in this same
    # transaction, so a failure rolls both back together.
    create_otp_record(
        email, "Email", purpose, otp, expiry_seconds, settings.otp_max_attempts
    )
    dispatch_email_otp(email, message, subject)

    return {"sent": True, "expires_in": expiry_seconds}


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
@rate_limit_bucket("email", clean_email, "email:verify")
@rate_limit(key=RATE_LIMIT_FIELD, limit=10, seconds=10 * 60, ip_based=False)
def verify_otp(email: str, otp: str, purpose: str = "Verification"):
    """Verify an OTP previously sent to the given email address."""
    settings = get_email_otp_settings()
    email = validate_single_email(email)

    return verify_otp_record(
        email, "Email", otp, clean_purpose(purpose), settings.otp_max_attempts
    )
