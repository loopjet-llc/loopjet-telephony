import secrets
import string
from functools import wraps

import frappe
from frappe import _
from frappe.utils import add_to_date, get_datetime, now_datetime

OTP_DOCTYPE = "TP OTP"

MAX_PURPOSE_LENGTH = 140

# Uniform on purpose: separate reasons would let a guest enumerate which
# recipients have a pending OTP.
GENERIC_FAILURE = {"verified": False, "reason": "invalid_or_expired"}

# Always overwritten, never read from the request, so a caller cannot
# nominate their own bucket.
RATE_LIMIT_FIELD = "tp_rate_limit_key"

# Shared by @rate_limit and rate_limit_bucket's own off-request enforcement.
GENERATE_LIMIT = 5
VERIFY_LIMIT = 10
RATE_LIMIT_WINDOW = 10 * 60

# One shared bucket for every uncanonicalizable recipient, so varying the
# garbage cannot mint fresh quota. Collides with no real recipient.
INVALID_RECIPIENT = "invalid"

# Keys are the values stored in TP OTP.channel.
OTP_CHANNELS = {
    "SMS": {"module": "telephony.twilio.sms", "recipient_field": "phone_number"},
    "Email": {"module": "telephony.email_otp", "recipient_field": "email"},
}


_DUMMY_HASH = None


def generate_otp_code(length: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def equalize_verify_cost():
    """Spend a KDF round on the paths that never reach a real comparison, so
    latency does not leak what GENERIC_FAILURE hides. Not constant-time."""
    global _DUMMY_HASH

    from passlib.hash import pbkdf2_sha256

    if _DUMMY_HASH is None:
        _DUMMY_HASH = pbkdf2_sha256.hash("timing-equalizer")

    pbkdf2_sha256.verify("", _DUMMY_HASH)


def clean_purpose(purpose: str) -> str:
    """Purpose is caller-supplied and used as a query filter, so bound it."""
    purpose = (purpose or "").strip() or "Verification"
    if len(purpose) > MAX_PURPOSE_LENGTH:
        frappe.throw(
            _("Purpose cannot be longer than {0} characters.").format(
                MAX_PURPOSE_LENGTH
            )
        )
    return purpose


def enforce_rate_limit(bucket, limit, seconds):
    """Apply the cap ``@rate_limit`` skips when there is no HTTP request."""
    key = frappe.cache.make_key(f"tp-otp-rl:{bucket}:{seconds}")

    count = frappe.cache.incrby(key, 1)
    if count == 1:
        frappe.cache.expire(key, seconds)

    if count > limit:
        frappe.throw(
            _(
                "You hit the rate limit because of too many requests."
                " Please try after sometime."
            ),
            frappe.RateLimitExceededError,
        )


def rate_limit_bucket(field, normalizer, scope, limit, seconds):
    """Publish a canonical, endpoint-scoped rate-limit key into ``form_dict``:
    ``@rate_limit`` buckets on the raw value and its own key collides across
    endpoints. Apply above it, with matching ``limit``/``seconds``."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            normalized = normalizer(frappe.cstr(frappe.form_dict.get(field)))
            # Bucket set unconditionally so the limiter is never keyless.
            if field in frappe.form_dict:
                frappe.form_dict[field] = normalized
            bucket = f"{scope}:{normalized or INVALID_RECIPIENT}"
            frappe.form_dict[RATE_LIMIT_FIELD] = bucket

            # @rate_limit below is inert without a request, so stand in for it.
            if not frappe.request:
                enforce_rate_limit(bucket, limit, seconds)

            return fn(*args, **kwargs)

        return wrapper

    return decorator


def consume_pending_otps(recipient, channel, purpose, max_attempts) -> int:
    """Expire outstanding OTPs for this recipient and return attempts already
    spent, so a resend cannot mint a fresh budget. Once it is spent, refuse
    rather than issue a code that would push the lockout further out."""
    # Locked: two concurrent generates would otherwise leave two live OTPs, of
    # which only the newest can verify. Query builder, for for_update().
    otp = frappe.qb.DocType(OTP_DOCTYPE)
    pending = (
        frappe.qb.from_(otp)
        .select(otp.name, otp.attempts)
        .where(
            (otp.recipient == recipient)
            & (otp.channel == channel)
            & (otp.purpose == purpose)
            & (otp.is_verified == 0)
            & (otp.expires_at > now_datetime())
        )
        .for_update()
        .run(as_dict=True)
    )
    if not pending:
        return 0

    spent_attempts = sum(row.attempts or 0 for row in pending)
    if spent_attempts >= max_attempts:
        frappe.throw(
            _("Too many incorrect attempts. Please try again later."),
            frappe.ValidationError,
        )

    already_expired = add_to_date(now_datetime(), seconds=-1)
    for row in pending:
        # Expired rather than deleted — the row is an audit record.
        frappe.db.set_value(
            OTP_DOCTYPE, row.name, "expires_at", already_expired, update_modified=False
        )

    return spent_attempts


def create_otp_record(
    recipient,
    channel,
    purpose,
    otp,
    expiry_seconds,
    max_attempts,
    notification_log=None,
):
    from passlib.hash import pbkdf2_sha256

    spent_attempts = consume_pending_otps(recipient, channel, purpose, max_attempts)

    doc = frappe.get_doc(
        {
            "doctype": OTP_DOCTYPE,
            "recipient": recipient,
            "channel": channel,
            "purpose": purpose,
            "otp_hash": pbkdf2_sha256.hash(otp),
            "attempts": spent_attempts,
            "expires_at": add_to_date(now_datetime(), seconds=expiry_seconds),
            "notification_log": notification_log,
        }
    )
    doc.insert(ignore_permissions=True)
    return doc


def verify_otp_record(recipient, channel, otp, purpose, max_attempts):
    from passlib.hash import pbkdf2_sha256

    otp_name = frappe.db.get_value(
        OTP_DOCTYPE,
        {
            "recipient": recipient,
            "channel": channel,
            "purpose": purpose,
            "is_verified": 0,
        },
        "name",
        order_by="creation desc",
    )
    if not otp_name:
        equalize_verify_cost()
        return dict(GENERIC_FAILURE)

    # Locked: concurrent verifies would otherwise share a stale `attempts`
    # count and collectively exceed otp_max_attempts.
    otp_doc = frappe.get_doc(OTP_DOCTYPE, otp_name, for_update=True)

    if get_datetime(otp_doc.expires_at) < now_datetime():
        equalize_verify_cost()
        return dict(GENERIC_FAILURE)

    if otp_doc.attempts >= max_attempts:
        equalize_verify_cost()
        return dict(GENERIC_FAILURE)

    if not pbkdf2_sha256.verify(otp, otp_doc.otp_hash):
        otp_doc.attempts += 1
        otp_doc.save(ignore_permissions=True)
        return dict(GENERIC_FAILURE)

    otp_doc.is_verified = 1
    otp_doc.verified_at = now_datetime()
    otp_doc.save(ignore_permissions=True)

    return {"verified": True}


# --- Entry points for other apps ------------------------------------------
#
# telephony.email_otp and telephony.twilio.sms are the HTTP API; server-side
# callers use send_otp / verify_otp instead of reaching into a channel module.


def get_otp_channel(channel: str) -> dict:
    """Resolve a channel name against OTP_CHANNELS. The name selects a module
    to import, so it is never taken on trust."""
    if channel not in OTP_CHANNELS:
        frappe.throw(
            _("{0} is not a supported OTP channel. Use one of: {1}.").format(
                channel, ", ".join(OTP_CHANNELS)
            )
        )

    return OTP_CHANNELS[channel]


def call_channel_endpoint(channel: str, method: str, recipient: str, **kwargs):
    """Call a channel's OTP endpoint the way an HTTP request would: they bucket
    their rate limit on ``form_dict[recipient_field]``, so publish the recipient
    there, then restore form_dict — it belongs to the caller's request."""
    config = get_otp_channel(channel)
    field = config["recipient_field"]
    endpoint = frappe.get_attr(f"{config['module']}.{method}")

    borrowed = {}
    for key in (field, RATE_LIMIT_FIELD):
        if key in frappe.form_dict:
            borrowed[key] = frappe.form_dict[key]

    frappe.form_dict[field] = recipient
    try:
        return endpoint(**{field: recipient}, **kwargs)
    finally:
        for key in (field, RATE_LIMIT_FIELD):
            if key in borrowed:
                frappe.form_dict[key] = borrowed[key]
            else:
                frappe.form_dict.pop(key, None)


def send_otp(recipient: str, channel: str, purpose: str = "Verification") -> dict:
    """Generate an OTP and deliver it to ``recipient`` over ``channel``; the
    code is never returned. ``purpose`` scopes the OTP, so callers verifying a
    specific record should name that record in it."""
    return call_channel_endpoint(channel, "generate_otp", recipient, purpose=purpose)


def verify_otp(
    recipient: str, channel: str, otp: str, purpose: str = "Verification"
) -> dict:
    """Verify an OTP previously sent to ``recipient`` over ``channel``. A failed
    verification is the only thing returned as a value — a bad channel, an
    unusable recipient and the rate limit all raise — and callers must not turn
    that value into a raise, which would roll back the recorded attempt."""
    return call_channel_endpoint(
        channel, "verify_otp", recipient, otp=otp, purpose=purpose
    )
