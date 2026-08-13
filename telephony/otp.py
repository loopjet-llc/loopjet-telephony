import secrets
import string
from functools import wraps

import frappe
from frappe import _
from frappe.utils import add_to_date, get_datetime, now_datetime

OTP_DOCTYPE = "TP OTP"

MAX_PURPOSE_LENGTH = 140

# Guest-facing verification failures are deliberately indistinguishable from
# one another. Reporting "no such OTP" separately from "wrong code" lets an
# unauthenticated caller enumerate which recipients have a pending OTP and
# what state it is in.
GENERIC_FAILURE = {"verified": False, "reason": "invalid_or_expired"}

# The form_dict field @rate_limit is pointed at. Always overwritten, never read
# from the request, so a caller cannot nominate their own bucket.
RATE_LIMIT_FIELD = "tp_rate_limit_key"

# Bucket for any recipient that could not be canonicalized. Neither a valid
# phone number nor a valid email address, so it can never collide with a real
# recipient's quota; parking every unusable spelling in one shared bucket is
# what stops a caller from minting fresh quota by varying the garbage.
INVALID_RECIPIENT = "invalid"


_DUMMY_HASH = None


def generate_otp_code(length: int) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def equalize_verify_cost():
    """Spend a KDF round on the paths that never reach a real comparison.

    GENERIC_FAILURE makes every failure look alike in the *body*, but not in
    the clock: only the wrong-code path runs pbkdf2 (~29k rounds), so without
    this a guest can tell "no live OTP for this recipient" from "there is one"
    purely by response latency — recovering what the generic reason hides.

    This does not make verification constant-time: the wrong-code path also
    writes the incremented attempt count, which the others do not. It closes
    the KDF-sized gap, which is the part big enough to measure over a network.
    """
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


def rate_limit_bucket(field, normalizer, scope):
    """Publish a canonical, endpoint-scoped rate-limit key into ``form_dict``.

    ``@rate_limit`` cannot be pointed straight at the caller's field, for two
    independent reasons:

    1. It buckets on ``frappe.form_dict[key]`` verbatim, so ``+911234500001``,
       ``+91 1234500001`` and ``+91-1234500001`` are three buckets for one
       recipient — a formatting loop would walk straight past the send cap.
    2. Its cache key is ``rl:{form_dict.cmd}:{identity}:{seconds}``, and only
       ``/api/v1`` populates ``cmd``. Over ``/api/v2`` it renders as ``None``,
       so two endpoints sharing a key field and a window collide on a single
       counter — failed verifies would eat the resend quota and vice versa.

    So normalize the value, qualify it with a per-endpoint ``scope``, and point
    ``@rate_limit`` at the field written here instead of at the raw one.

    ``normalizer`` runs on unvalidated input and must not throw. Anything it
    cannot canonicalize lands in the shared ``INVALID_RECIPIENT`` bucket — the
    endpoint's own validation rejects it a moment later, and the limiter still
    has a non-empty key to work with (with ``ip_based=False`` an empty one makes
    ``rate_limit`` throw its own "Either key or IP flag is required" instead).

    Must be applied *above* ``@rate_limit`` so it runs first.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            normalized = normalizer(frappe.form_dict.get(field))
            # Only rewrite the caller's field if they actually sent it; the
            # bucket is set unconditionally so the limiter is never keyless.
            if field in frappe.form_dict:
                frappe.form_dict[field] = normalized
            frappe.form_dict[
                RATE_LIMIT_FIELD
            ] = f"{scope}:{normalized or INVALID_RECIPIENT}"
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def consume_pending_otps(recipient, channel, purpose, max_attempts) -> int:
    """Expire outstanding OTPs for this recipient and return attempts already
    spent against them.

    ``verify_otp_record`` only ever reads the newest unverified row, and
    ``attempts`` lives on that row. Without carrying the count forward, each
    ``generate_otp`` call would hand out a fresh ``otp_max_attempts`` budget
    against the same short code space. Carrying forward only from *live* rows
    means the budget still resets naturally once the window lapses.

    Once that carried budget is spent, refuse rather than issue another code.
    The new row would start at the cap *and* carry a fresh ``expires_at``, so
    each resend pushed the lockout a full window further out while billing for
    a code that could never verify — a user who responds to being locked out by
    retrying, which is the normal response, kept themselves locked out forever.
    Refusing leaves the live row's expiry untouched, so the lockout drains on
    its own no matter how often it is retried.

    This does make "locked out" distinguishable from "not", unlike the uniform
    GENERIC_FAILURE on the verify side. That is accepted: reaching this state
    requires ``max_attempts`` failed verifies against a live OTP, which a caller
    can only arrange for a recipient they are already able to target, so it
    reveals nothing they could not have caused themselves.
    """
    pending = frappe.get_all(
        OTP_DOCTYPE,
        filters={
            "recipient": recipient,
            "channel": channel,
            "purpose": purpose,
            "is_verified": 0,
            "expires_at": (">", now_datetime()),
        },
        fields=["name", "attempts"],
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

    # Locked: reading and incrementing `attempts` is a read-modify-write, so
    # concurrent verifies would otherwise share a stale count and collectively
    # exceed otp_max_attempts.
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
