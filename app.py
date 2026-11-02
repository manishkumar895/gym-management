import os
import re
import calendar
import secrets
import sqlite3
import tempfile
import time
import atexit
import smtplib
import ssl
from email.message import EmailMessage
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
from io import BytesIO
from contextlib import contextmanager
from datetime import date, timedelta, datetime
import pytz
import requests
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask import send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DATABASE = BASE_DIR / "database.db"
def load_secret_key(secret_path):
    """Use a configured key or create a persistent local session-signing key."""
    configured_key = os.environ.get("SECRET_KEY")
    if configured_key:
        return configured_key
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        secret_key = secrets.token_hex(32)
        with secret_path.open("x", encoding="utf-8") as secret_file:
            secret_file.write(secret_key)
        return secret_key
    except FileExistsError:
        for _ in range(50):
            secret_key = secret_path.read_text(encoding="utf-8").strip()
            if secret_key:
                return secret_key
            time.sleep(0.02)
        raise RuntimeError(f"The Flask session key file is empty: {secret_path}")
app = Flask(__name__)
app.config["SECRET_KEY"] = load_secret_key(
    Path(app.instance_path) / "secret_key"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "SESSION_COOKIE_SECURE", ""
).lower() in {"1", "true", "yes"}
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.config["ADMIN_USERNAME"] = os.environ.get("ADMIN_USERNAME", "admin")
app.config["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "admin123")
app.config["ADMIN_CREDENTIALS_CONFIGURED"] = (
    "ADMIN_USERNAME" in os.environ or "ADMIN_PASSWORD" in os.environ
)
app.config["DEMO_MODE"] = os.environ.get("DEMO_MODE", "0").lower() in {
    "1",
    "true",
    "yes",
}
# Email SMTP configuration. Store credentials in .env, never in source code.*
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com").strip()
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "").strip()
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "").replace(" ", "").strip()
app.config["MAIL_FROM"] = os.environ.get("MAIL_FROM", app.config["MAIL_USERNAME"]).strip()
app.config["MAIL_USE_SSL"] = os.environ.get("MAIL_USE_SSL", "false").lower() in {"1", "true", "yes"}
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "true").lower() in {"1", "true", "yes"}
app.config["MAIL_TIMEZONE"] = os.environ.get("MAIL_TIMEZONE", "Asia/Kolkata").strip()

# WhatsApp Cloud API configuration. Keep tokens in .env, never in source code.
app.config["WHATSAPP_ACCESS_TOKEN"] = os.environ.get("WHATSAPP_ACCESS_TOKEN", "").strip()
app.config["WHATSAPP_PHONE_NUMBER_ID"] = os.environ.get("WHATSAPP_PHONE_NUMBER_ID", "").strip()
app.config["WHATSAPP_API_VERSION"] = os.environ.get("WHATSAPP_API_VERSION", "vXX.X").strip()
app.config["WHATSAPP_TEMPLATE_WELCOME"] = os.environ.get("WHATSAPP_TEMPLATE_WELCOME", "gym_welcome").strip()
app.config["WHATSAPP_TEMPLATE_7_DAY"] = os.environ.get("WHATSAPP_TEMPLATE_7_DAY", "gym_expiry_7d").strip()
app.config["WHATSAPP_TEMPLATE_3_DAY"] = os.environ.get("WHATSAPP_TEMPLATE_3_DAY", "gym_expiry_3d").strip()
app.config["WHATSAPP_TEMPLATE_EXPIRY"] = os.environ.get("WHATSAPP_TEMPLATE_EXPIRY", "gym_expiry_today").strip()
app.config["WHATSAPP_TEMPLATE_PAYMENT"] = os.environ.get("WHATSAPP_TEMPLATE_PAYMENT", "gym_payment_received").strip()

@contextmanager
def get_db_connection():
    """Open a database connection and close it after each operation."""
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
def init_db():
    """Create application tables and bootstrap one admin if needed."""
    with get_db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT,
                username TEXT NOT NULL UNIQUE,
                email TEXT,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # Migrate existing username/password-only admin tables.*
        admin_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(admins)").fetchall()
        }
        if "full_name" not in admin_columns:
            connection.execute("ALTER TABLE admins ADD COLUMN full_name TEXT")
        if "email" not in admin_columns:
            connection.execute("ALTER TABLE admins ADD COLUMN email TEXT")
        if "created_at" not in admin_columns:
            connection.execute("ALTER TABLE admins ADD COLUMN created_at TIMESTAMP")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_email "
            "ON admins (email) WHERE email IS NOT NULL AND email != ''"
        )
        admin = connection.execute(
            "SELECT id FROM admins ORDER BY id LIMIT 1"
        ).fetchone()
        # Bootstrap only when credentials are explicitly configured.*
        # Otherwise, the first admin is created through /register.*
        if admin is None and app.config["ADMIN_CREDENTIALS_CONFIGURED"]:
            password_hash = generate_password_hash(app.config["ADMIN_PASSWORD"])
            connection.execute(
                """
                INSERT INTO admins (full_name, username, email, password_hash)
                VALUES (?, ?, ?, ?)
                """,
                ("Administrator", app.config["ADMIN_USERNAME"], None, password_hash),
            )
        elif admin is not None and app.config["ADMIN_CREDENTIALS_CONFIGURED"]:
            password_hash = generate_password_hash(app.config["ADMIN_PASSWORD"])
            connection.execute(
                "UPDATE admins SET username = ?, password_hash = ? WHERE id = ?",
                (app.config["ADMIN_USERNAME"], password_hash, admin["id"]),
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT,
                age INTEGER NOT NULL,
                gender TEXT NOT NULL,
                joining_date TEXT NOT NULL,
                membership_plan TEXT NOT NULL,
                monthly_fee REAL NOT NULL,
                start_date TEXT NOT NULL,
                due_date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active'
                    CHECK (status IN ('Active', 'Inactive')),
                notes TEXT
            )
            """
        )
        # Email consent is separate from any legacy WhatsApp preference.*
        member_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(members)").fetchall()
        }
        if "email_opt_in" not in member_columns:
            connection.execute(
                "ALTER TABLE members ADD COLUMN email_opt_in INTEGER NOT NULL DEFAULT 0"
            )
        if "whatsapp_opt_in" not in member_columns:
            connection.execute(
                "ALTER TABLE members ADD COLUMN whatsapp_opt_in INTEGER NOT NULL DEFAULT 0"
            )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS whatsapp_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id INTEGER NOT NULL,
                message_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                recipient TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('sending', 'sent', 'failed')),
                message_id TEXT,
                attempts INTEGER NOT NULL DEFAULT 1,
                error_message TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                sent_at TEXT,
                FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE,
                UNIQUE(member_id, message_type, dedupe_key)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_whatsapp_logs_status ON whatsapp_logs(status, updated_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS email_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id INTEGER NOT NULL,
                reminder_type TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                recipient TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('sending', 'sent', 'failed')),
                attempts INTEGER NOT NULL DEFAULT 1,
                error_message TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                sent_at TEXT,
                FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE,
                UNIQUE(member_id, expiry_date, reminder_type)
            )
            """
        )
        # Migrate email_logs created by an earlier version.*
        email_log_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(email_logs)").fetchall()
        }
        if "updated_at" not in email_log_columns:
            connection.execute(
                "ALTER TABLE email_logs ADD COLUMN updated_at TEXT"
            )
            connection.execute(
                "UPDATE email_logs SET updated_at = COALESCE(sent_at, created_at, CURRENT_TIMESTAMP) "
                "WHERE updated_at IS NULL"
            )
        if "error_message" not in email_log_columns:
            connection.execute("ALTER TABLE email_logs ADD COLUMN error_message TEXT")
        if "sent_at" not in email_log_columns:
            connection.execute("ALTER TABLE email_logs ADD COLUMN sent_at TEXT")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_logs_created_at "
            "ON email_logs(created_at DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_logs_status "
            "ON email_logs(status, updated_at)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_id INTEGER NOT NULL,
                payment_date TEXT NOT NULL,
                amount REAL NOT NULL CHECK (amount > 0),
                payment_method TEXT NOT NULL CHECK (
                    payment_method IN ('Cash', 'UPI', 'Card', 'Bank Transfer')
                ),
                transaction_id TEXT,
                notes TEXT,
                duration_months INTEGER NOT NULL DEFAULT 1,
                start_date TEXT,
                expiry_date TEXT,
                submission_token TEXT UNIQUE,
                FOREIGN KEY (member_id) REFERENCES members (id) ON DELETE RESTRICT
            )
            """
        )
        payment_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(payments)").fetchall()
        }
        migrate_payment_membership = "duration_months" not in payment_columns
        if migrate_payment_membership:
            connection.execute(
                "ALTER TABLE payments ADD COLUMN duration_months "
                "INTEGER NOT NULL DEFAULT 1"
            )
        if "start_date" not in payment_columns:
            connection.execute("ALTER TABLE payments ADD COLUMN start_date TEXT")
        if "expiry_date" not in payment_columns:
            connection.execute("ALTER TABLE payments ADD COLUMN expiry_date TEXT")
        if "membership_plan" not in payment_columns:
            connection.execute(
                "ALTER TABLE payments ADD COLUMN membership_plan TEXT"
            )
        if "member_name" not in payment_columns:
            connection.execute("ALTER TABLE payments ADD COLUMN member_name TEXT")
        if "member_phone" not in payment_columns:
            connection.execute("ALTER TABLE payments ADD COLUMN member_phone TEXT")
        if "submission_token" not in payment_columns:
            connection.execute("ALTER TABLE payments ADD COLUMN submission_token TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_submission_token "
            "ON payments (submission_token)"
        )
        legacy_payments = connection.execute(
            "SELECT id, member_id, payment_date FROM payments "
            "WHERE start_date IS NULL OR expiry_date IS NULL "
            "OR membership_plan IS NULL OR member_name IS NULL "
            "OR member_phone IS NULL"
        ).fetchall()
        for payment in legacy_payments:
            payment_date = date.fromisoformat(payment["payment_date"])
            member = connection.execute(
                "SELECT name, phone, membership_plan FROM members WHERE id = ?",
                (payment["member_id"],),
            ).fetchone()
            connection.execute(
                "UPDATE payments SET start_date = COALESCE(start_date, ?), "
                "expiry_date = COALESCE(expiry_date, ?), "
                "membership_plan = COALESCE(membership_plan, ?), "
                "member_name = COALESCE(member_name, ?), "
                "member_phone = COALESCE(member_phone, ?) WHERE id = ?",
                (
                    payment_date.isoformat(),
                    next_month(payment_date).isoformat(),
                    member["membership_plan"],
                    member["name"],
                    member["phone"],
                    payment["id"],
                ),
            )
        if migrate_payment_membership:
            current_memberships = connection.execute(
                """
                SELECT members.id, payments.start_date, payments.expiry_date
                FROM members
                JOIN payments ON payments.id = (
                    SELECT latest.id FROM payments AS latest
                    WHERE latest.member_id = members.id
                    ORDER BY latest.payment_date DESC, latest.id DESC LIMIT 1
                )
                """
            ).fetchall()
            for membership in current_memberships:
                connection.execute(
                    "UPDATE members SET start_date = ?, due_date = ? WHERE id = ?",
                    (
                        membership["start_date"],
                        membership["expiry_date"],
                        membership["id"],
                    ),
                )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_payments_member_date "
            "ON payments (member_id, payment_date DESC)"
        )
MAX_EMAIL_ATTEMPTS = 5
STALE_EMAIL_SECONDS = 10 * 60
def email_is_configured():
    return bool(
        app.config["MAIL_SERVER"]
        and app.config["MAIL_PORT"]
        and app.config["MAIL_USERNAME"]
        and app.config["MAIL_PASSWORD"]
        and app.config["MAIL_FROM"]
    )
def build_member_email(member, reminder_type):
    """Build subject and plain-text body for welcome and expiry reminders."""
    expiry = date.fromisoformat(member["due_date"]).strftime("%d %B %Y")
    name = member["name"]
    plan = member["membership_plan"]
    gym_name = GYM_NAME
    if reminder_type == "welcome":
        start = date.fromisoformat(member["start_date"]).strftime("%d %B %Y")
        subject = f"Welcome to {gym_name}"
        body = (
            f"Hello {name},\n\n"
            f"Welcome to {gym_name}! Your membership has been registered.\n\n"
            f"Membership plan: {plan}\n"
            f"Start date: {start}\n"
            f"Expiry date: {expiry}\n\n"
            "Thank you for joining us.\n"
            f"{gym_name}"
        )
    elif reminder_type == "7_day":
        subject = f"Your {gym_name} membership expires in 7 days"
        body = (
            f"Hello {name},\n\nYour {plan} membership at {gym_name} "
            f"expires in 7 days, on {expiry}.\n\n"
            "Please renew your membership to continue your training.\n\n"
            f"{gym_name}"
        )
    elif reminder_type == "3_day":
        subject = f"Your {gym_name} membership expires in 3 days"
        body = (
            f"Hello {name},\n\nYour {plan} membership at {gym_name} "
            f"expires in 3 days, on {expiry}.\n\n"
            "Please renew your membership soon.\n\n"
            f"{gym_name}"
        )
    elif reminder_type == "expiry_day":
        subject = f"Your {gym_name} membership expires today"
        body = (
            f"Hello {name},\n\nYour {plan} membership at {gym_name} "
            f"expires today, {expiry}.\n\n"
            "Please contact the gym to renew your membership.\n\n"
            f"{gym_name}"
        )
    else:
        raise ValueError("Unsupported email reminder type.")
    return subject, body
def _claim_email_log(member, reminder_type, recipient, force_retry=False):
    """Atomically claim one reminder using SQLite's write lock and unique key."""
    now = datetime.now(pytz.UTC)
    now_text = now.isoformat()
    with get_db_connection() as connection:
        # Serializes competing workers before they inspect or update the log.*
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT id, status, attempts, updated_at FROM email_logs "
            "WHERE member_id = ? AND expiry_date = ? AND reminder_type = ?",
            (member["id"], member["due_date"], reminder_type),
        ).fetchone()
        if existing:
            if existing["status"] == "sent":
                return None
            if existing["status"] == "sending":
                # A crashed process may leave a stale sending claim. Only reclaim*
                # it after the timeout; a live sender keeps its claim.*
                try:
                    last_update = datetime.fromisoformat(existing["updated_at"])
                    if last_update.tzinfo is None:
                        last_update = last_update.replace(tzinfo=pytz.UTC)
                    age_seconds = (now - last_update.astimezone(pytz.UTC)).total_seconds()
                except (TypeError, ValueError):
                    age_seconds = STALE_EMAIL_SECONDS + 1
                if age_seconds < STALE_EMAIL_SECONDS:
                    return None
            if existing["attempts"] >= MAX_EMAIL_ATTEMPTS and not force_retry:
                return None
            connection.execute(
                "UPDATE email_logs SET status = 'sending', attempts = attempts + 1, "
                "recipient = ?, error_message = NULL, updated_at = ? WHERE id = ?",
                (recipient, now_text, existing["id"]),
            )
            return existing["id"]
        cursor = connection.execute(
            "INSERT INTO email_logs "
            "(member_id, reminder_type, expiry_date, recipient, status, attempts, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, 'sending', 1, ?, ?)",
            (member["id"], reminder_type, member["due_date"], recipient, now_text, now_text),
        )
        return cursor.lastrowid
def _finish_email_log(log_id, status, error_message=None):
    with get_db_connection() as connection:
        connection.execute(
            "UPDATE email_logs SET status = ?, error_message = ?, updated_at = ?, "
            "sent_at = CASE WHEN ? = 'sent' THEN CURRENT_TIMESTAMP ELSE sent_at END "
            "WHERE id = ?",
            (status, error_message, datetime.now(pytz.UTC).isoformat(), status, log_id),
        )
def send_member_email(member, reminder_type, force_retry=False):
    """Send one email through SMTP and persist the result in SQLite."""
    if reminder_type not in {"welcome", "7_day", "3_day", "expiry_day"}:
        raise ValueError("Unsupported email reminder type.")
    recipient = (member["email"] or "").strip()
    if not recipient:
        return False, "Member does not have an email address."
    if not member["email_opt_in"]:
        return False, "Member has not opted in to email notifications."
    log_id = _claim_email_log(member, reminder_type, recipient, force_retry=force_retry)
    if log_id is None:
        return False, "This email has already been sent or is currently being sent."
    if not email_is_configured():
        detail = "SMTP is not configured. Set MAIL_USERNAME and MAIL_PASSWORD in .env."
        _finish_email_log(log_id, "failed", detail)
        return False, detail
    try:
        subject, body = build_member_email(member, reminder_type)
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = app.config["MAIL_FROM"]
        message["To"] = recipient
        message.set_content(body)
        host = app.config["MAIL_SERVER"]
        port = app.config["MAIL_PORT"]
        timeout = 25
        if app.config["MAIL_USE_SSL"]:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=timeout) as smtp:
                smtp.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if app.config["MAIL_USE_TLS"]:
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                smtp.login(app.config["MAIL_USERNAME"], app.config["MAIL_PASSWORD"])
                smtp.send_message(message)
        _finish_email_log(log_id, "sent")
        return True, "SMTP server accepted the email."
    except Exception as exc:
        app.logger.exception("Email send failed for member %s", member["id"])
        _finish_email_log(log_id, "failed", str(exc)[:1000])
        return False, str(exc)
def run_membership_reminders():
    """Send 7-, 3- and 0-day reminders; failed attempts are retried on later scans."""
    today = datetime.now(pytz.timezone(app.config["MAIL_TIMEZONE"])).date()
    offsets = {7: "7_day", 3: "3_day", 0: "expiry_day"}
    with get_db_connection() as connection:
        members_to_check = connection.execute(
            "SELECT * FROM members WHERE status = 'Active' "
            "AND email_opt_in = 1 AND email IS NOT NULL AND email != ''"
        ).fetchall()
    sent_count = 0
    for member in members_to_check:
        try:
            days_left = (date.fromisoformat(member["due_date"]) - today).days
        except (TypeError, ValueError):
            app.logger.warning("Invalid due date for member %s", member["id"])
            continue
        reminder_type = offsets.get(days_left)
        if reminder_type:
            success, detail = send_member_email(member, reminder_type)
            if success:
                sent_count += 1
            elif "already been sent" not in detail:
                app.logger.warning(
                    "Email reminder %s for member %s was not sent: %s",
                    reminder_type, member["id"], detail,
                )
    return sent_count
def whatsapp_is_configured():
    version = app.config["WHATSAPP_API_VERSION"]
    return bool(
        app.config["WHATSAPP_ACCESS_TOKEN"]
        and app.config["WHATSAPP_PHONE_NUMBER_ID"]
        and version and version != "vXX.X"
    )


def normalize_whatsapp_phone(phone):
    digits = re.sub(r"\D", "", str(phone or ""))
    if len(digits) == 10:
        digits = "91" + digits
    if not 10 <= len(digits) <= 15:
        raise ValueError("Invalid WhatsApp number. Use country code and number.")
    return digits


def _claim_whatsapp_log(member, message_type, dedupe_key):
    """Atomically claim a message so overlapping scheduler runs do not duplicate it."""
    now = datetime.now(pytz.UTC).isoformat()
    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM whatsapp_logs WHERE member_id=? AND message_type=? AND dedupe_key=?",
            (member["id"], message_type, dedupe_key),
        ).fetchone()
        if row:
            if row["status"] == "sent" or row["status"] == "sending":
                return None
            if row["attempts"] >= 5:
                return None
            connection.execute(
                "UPDATE whatsapp_logs SET status='sending', attempts=attempts+1, "
                "recipient=?, error_message=NULL, updated_at=? WHERE id=?",
                (normalize_whatsapp_phone(member["phone"]), now, row["id"]),
            )
            return row["id"]
        cursor = connection.execute(
            "INSERT INTO whatsapp_logs (member_id,message_type,dedupe_key,recipient,status,attempts,created_at,updated_at) "
            "VALUES (?,?,?,?, 'sending',1,?,?)",
            (member["id"], message_type, dedupe_key, normalize_whatsapp_phone(member["phone"]), now, now),
        )
        return cursor.lastrowid


def _finish_whatsapp_log(log_id, status, message_id=None, error_message=None):
    with get_db_connection() as connection:
        connection.execute(
            "UPDATE whatsapp_logs SET status=?, message_id=?, error_message=?, updated_at=?, "
            "sent_at=CASE WHEN ?='sent' THEN CURRENT_TIMESTAMP ELSE sent_at END WHERE id=?",
            (status, message_id, error_message, datetime.now(pytz.UTC).isoformat(), status, log_id),
        )


def send_whatsapp_template(member, message_type, parameters, dedupe_key=None):
    """Send one approved Meta template and save its result in SQLite."""
    if not member["whatsapp_opt_in"]:
        return False, "Member has not consented to WhatsApp notifications."
    if not whatsapp_is_configured():
        return False, "WhatsApp Cloud API is not configured in .env."
    template_names = {
        "welcome": app.config["WHATSAPP_TEMPLATE_WELCOME"],
        "7_day": app.config["WHATSAPP_TEMPLATE_7_DAY"],
        "3_day": app.config["WHATSAPP_TEMPLATE_3_DAY"],
        "expiry_day": app.config["WHATSAPP_TEMPLATE_EXPIRY"],
        "payment": app.config["WHATSAPP_TEMPLATE_PAYMENT"],
    }
    template_name = template_names.get(message_type)
    if not template_name:
        raise ValueError("Unsupported WhatsApp message type.")
    dedupe_key = dedupe_key or (member["due_date"] if message_type != "welcome" else "welcome")
    try:
        log_id = _claim_whatsapp_log(member, message_type, dedupe_key)
    except ValueError as exc:
        return False, str(exc)
    if log_id is None:
        return False, "This WhatsApp message was already sent or is currently being sent."

    url = (
        f"https://graph.facebook.com/{app.config['WHATSAPP_API_VERSION']}/"
        f"{app.config['WHATSAPP_PHONE_NUMBER_ID']}/messages"
    )
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": normalize_whatsapp_phone(member["phone"]),
        "type": "template",
        "template": {
            "name": template_name,
            "language": {"code": "en"},
            "components": [{
                "type": "body",
                "parameters": [{"type": "text", "text": str(value)} for value in parameters],
            }],
        },
    }
    try:
        response = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {app.config['WHATSAPP_ACCESS_TOKEN']}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )
        try:
            result = response.json()
        except ValueError:
            result = {"error": response.text[:1000]}
        if not response.ok:
            raise RuntimeError(str(result)[:1000])
        messages = result.get("messages") or []
        message_id = messages[0].get("id") if messages else None
        _finish_whatsapp_log(log_id, "sent", message_id=message_id)
        return True, "WhatsApp API accepted the message."
    except Exception as exc:
        app.logger.exception("WhatsApp send failed for member %s", member["id"])
        _finish_whatsapp_log(log_id, "failed", error_message=str(exc)[:1000])
        return False, str(exc)


def run_whatsapp_membership_reminders():
    """Send consented members their 7-, 3-, and 0-day membership reminders."""
    today = datetime.now(pytz.timezone(app.config["MAIL_TIMEZONE"])).date()
    offsets = {7: "7_day", 3: "3_day", 0: "expiry_day"}
    with get_db_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM members WHERE status='Active' AND whatsapp_opt_in=1"
        ).fetchall()
    sent_count = 0
    for member in rows:
        try:
            days_left = (date.fromisoformat(member["due_date"]) - today).days
        except (TypeError, ValueError):
            app.logger.warning("Invalid due date for WhatsApp member %s", member["id"])
            continue
        reminder_type = offsets.get(days_left)
        if reminder_type:
            expiry = date.fromisoformat(member["due_date"]).strftime("%d %B %Y")
            ok, detail = send_whatsapp_template(
                member, reminder_type, [member["name"], expiry]
            )
            if ok:
                sent_count += 1
            elif "already sent" not in detail and "currently being sent" not in detail:
                app.logger.warning("WhatsApp reminder for member %s: %s", member["id"], detail)
    return sent_count


def start_reminder_scheduler():
    """Start one scheduler process; SQLite uniqueness prevents duplicate reminder rows."""
    scheduler = BackgroundScheduler(timezone=app.config["MAIL_TIMEZONE"])
    scheduler.add_job(
        run_membership_reminders,
        trigger="interval",
        minutes=15,
        id="membership_email_reminders",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler.running else None)
    return scheduler
def login_required(view):
    """Require an admin session unless the app is running in demo mode."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not app.config["DEMO_MODE"] and "admin_id" not in session:
            return redirect(url_for("login", next=request.full_path))
        return view(*args, **kwargs)
    return wrapped_view
def is_safe_redirect_target(target):
    """Allow only local paths for post-login redirects."""
    if not target or not target.startswith("/") or target.startswith("//"):
        return False
    return not urlsplit(target).netloc and "\\\\" not in target
PAYMENT_METHODS = ("Cash", "UPI", "Card", "Bank Transfer")
GYM_NAME = "Form & Function"
def add_months(date_value, months):
    """Move a date forward by whole months, clamping to the target month's end."""
    month_offset = date_value.month - 1 + months
    year = date_value.year + month_offset // 12
    month = month_offset % 12 + 1
    day = min(date_value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)
def next_month(date_value):
    """Move a date forward one month, clamping to that month's last day."""
    return add_months(date_value, 1)
def get_fee_info(connection, member):
    """Calculate a member's next fee date and its display status."""
    latest_payment = connection.execute(
        "SELECT payment_date FROM payments WHERE member_id = ? "
        "ORDER BY payment_date DESC, id DESC LIMIT 1",
        (member["id"],),
    ).fetchone()
    due_date = date.fromisoformat(member["due_date"])
    last_payment_date = latest_payment["payment_date"] if latest_payment else None
    days_until_due = (due_date - date.today()).days
    if days_until_due < 0:
        status = "Overdue"
    elif days_until_due == 0:
        status = "Due Today"
    elif days_until_due <= 7:
        status = "Due Soon"
    else:
        status = "Paid"
    return {
        "last_payment_date": last_payment_date,
        "next_due_date": due_date.isoformat(),
        "days_remaining": max(days_until_due, 0),
        "days_overdue": max(-days_until_due, 0),
        "fee_status": status,
    }
def build_reminder_message(member, fee_info):
    """Create a copyable reminder without contacting an external service."""
    due_date = date.fromisoformat(fee_info["next_due_date"])
    formatted_due_date = f"{due_date.day} {due_date.strftime('%B %Y')}"
    if fee_info["fee_status"] == "Overdue":
        overdue_days = fee_info["days_overdue"]
        day_label = "day" if overdue_days == 1 else "days"
        due_text = (
            f"was due on {formatted_due_date} and is "
            f"{overdue_days} {day_label} overdue"
        )
    else:
        due_text = f"is due on {formatted_due_date}"
    return (
        f"Hello {member['name']},\n"
        f"Your gym membership fee of ₹{member['monthly_fee']:g} {due_text}.\n"
        "Please make the payment to continue your membership.\n"
        "Thank you."
    )
def get_reminder_status(days_remaining):
    """Return the reminder template category for a membership expiry."""
    if days_remaining < 0:
        return "Expired-membership message"
    if days_remaining == 0:
        return "Expiry-day message"
    if days_remaining == 1:
        return "1-day reminder"
    if days_remaining <= 3:
        return "3-day reminder"
    if days_remaining <= 7:
        return "7-day reminder"
    return None
def build_membership_reminder_message(member, days_remaining):
    """Generate the predefined message matching a membership's expiry window."""
    status = get_reminder_status(days_remaining)
    if status is None:
        raise ValueError("A reminder is only available within 7 days of expiry.")
    expiry_date = date.fromisoformat(member["due_date"])
    formatted_expiry = f"{expiry_date.day} {expiry_date.strftime('%B %Y')}"
    templates = {
        "7-day reminder": (
            "Hello {name}, your gym membership expires on {expiry}. "
            "This is a friendly 7-day reminder to renew your membership. "
            "We hope to see you at the gym!"
        ),
        "3-day reminder": (
            "Hello {name}, your gym membership expires on {expiry}. "
            "There are {days} days left to renew your membership. "
            "We hope to see you at the gym!"
        ),
        "1-day reminder": (
            "Hello {name}, your gym membership expires tomorrow, "
            "{expiry}. Please renew to continue your training. Thank you!"
        ),
        "Expiry-day message": (
            "Hello {name}, your gym membership expires today, {expiry}. "
            "Please renew to continue your training. Thank you!"
        ),
        "Expired-membership message": (
            "Hello {name}, your gym membership expired on {expiry}. "
            "Please renew your membership before your next visit. Thank you!"
        ),
    }
    return templates[status].format(
        name=member["name"],
        expiry=formatted_expiry,
        days=days_remaining,
    )
def validate_payment(form):
    """Validate a payment form and return normalized values and errors."""
    values = {
        "member_id": form.get("member_id", "").strip(),
        "payment_date": form.get("payment_date", "").strip(),
        "amount": form.get("amount", "").strip(),
        "payment_method": form.get("payment_method", "").strip(),
        "transaction_id": form.get("transaction_id", "").strip(),
        "notes": form.get("notes", "").strip(),
    }
    has_membership_period = any(
        key in form for key in ("duration_months", "start_date", "expiry_date")
    )
    if not has_membership_period:
        values["duration_months"] = "1"
        values["start_date"] = values["payment_date"]
        try:
            values["expiry_date"] = next_month(
                date.fromisoformat(values["payment_date"])
            ).isoformat()
        except ValueError:
            values["expiry_date"] = ""
    else:
        values["duration_months"] = form.get("duration_months", "").strip()
        values["start_date"] = form.get("start_date", "").strip()
        values["expiry_date"] = form.get("expiry_date", "").strip()
    errors = []
    try:
        values["member_id"] = int(values["member_id"])
    except ValueError:
        errors.append("Select a valid member.")
    try:
        date.fromisoformat(values["payment_date"])
    except ValueError:
        errors.append("Enter a valid payment date.")
    try:
        values["amount"] = float(values["amount"])
        if not 0 < values["amount"] <= 1_000_000:
            errors.append("Payment amount must be greater than 0 and at most 1,000,000.")
    except ValueError:
        errors.append("Enter a valid payment amount.")
    if values["payment_method"] not in PAYMENT_METHODS:
        errors.append("Select a valid payment method.")
    try:
        values["duration_months"] = int(values["duration_months"])
        if not 1 <= values["duration_months"] <= 60:
            errors.append("Membership duration must be between 1 and 60 months.")
    except ValueError:
        errors.append("Enter a valid membership duration in months.")
    for field, label in (
        ("start_date", "membership start date"),
        ("expiry_date", "membership expiry date"),
    ):
        try:
            date.fromisoformat(values[field])
        except ValueError:
            errors.append(f"Enter a valid {label}.")
    try:
        expected_expiry = add_months(
            date.fromisoformat(values["start_date"]),
            values["duration_months"],
        ).isoformat()
        if values["expiry_date"] != expected_expiry:
            errors.append(
                "Membership expiry date must match its start date and duration."
            )
    except (ValueError, TypeError):
        pass
    if (
        values["start_date"]
        and values["expiry_date"]
        and values["expiry_date"] <= values["start_date"]
    ):
        errors.append("Membership expiry date must be after its start date.")
    if len(values["transaction_id"]) > 100:
        errors.append("Transaction/reference ID must be 100 characters or fewer.")
    if len(values["notes"]) > 1000:
        errors.append("Payment notes must be 1,000 characters or fewer.")
    return values, errors
def validate_member(form):
    """Validate and normalize member form data before it reaches SQLite."""
    values = {
        "name": form.get("name", "").strip(),
        "phone": form.get("phone", "").strip(),
        "email": form.get("email", "").strip(),
        "age": form.get("age", "").strip(),
        "gender": form.get("gender", "").strip(),
        "joining_date": form.get("joining_date", "").strip(),
        "membership_plan": form.get("membership_plan", "").strip(),
        "monthly_fee": form.get("monthly_fee", "").strip(),
        "start_date": form.get("start_date", "").strip(),
        "due_date": form.get("due_date", "").strip(),
        "status": form.get("status", "Active").strip(),
        "notes": form.get("notes", "").strip(),
        "email_opt_in": 1 if form.get("email_opt_in") in {"1", "on", "true", "yes"} else 0,
        "whatsapp_opt_in": 1 if form.get("whatsapp_opt_in") in {"1", "on", "true", "yes"} else 0,
    }
    errors = []
    if not values["name"]:
        errors.append("Full name is required.")
    elif len(values["name"]) > 100:
        errors.append("Full name must be 100 characters or fewer.")
    if not re.fullmatch(r"[+()\d\s.-]{7,20}", values["phone"]):
        errors.append("Enter a valid phone number (7 to 20 characters).")
    if values["email"] and (
        len(values["email"]) > 120
        or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", values["email"])
    ):
        errors.append("Enter a valid email address.")
    if values["email_opt_in"] and not values["email"]:
        errors.append("An email address is required when email reminders are enabled.")
    try:
        values["age"] = int(values["age"])
        if not 13 <= values["age"] <= 100:
            errors.append("Age must be between 13 and 100.")
    except ValueError:
        errors.append("Enter a valid age.")
    if values["gender"] not in {"Female", "Male", "Other", "Prefer not to say"}:
        errors.append("Select a valid gender option.")
    for field in ("joining_date", "start_date", "due_date"):
        try:
            date.fromisoformat(values[field])
        except ValueError:
            errors.append("Enter valid joining, start, and due dates.")
            break
    if values["start_date"] and values["due_date"] and values["due_date"] < values["start_date"]:
        errors.append("Due date cannot be earlier than the membership start date.")
    if not values["membership_plan"] or len(values["membership_plan"]) > 60:
        errors.append("Enter a membership plan (60 characters or fewer).")
    try:
        values["monthly_fee"] = float(values["monthly_fee"])
        if not 0 < values["monthly_fee"] <= 1_000_000:
            errors.append("Monthly fee must be greater than 0 and at most 1,000,000.")
    except ValueError:
        errors.append("Enter a valid monthly fee.")
    if values["status"] not in {"Active", "Inactive"}:
        errors.append("Select a valid member status.")
    if len(values["notes"]) > 1000:
        errors.append("Notes must be 1,000 characters or fewer.")
    return values, errors
@app.route("/")
@app.route("/dashboard")
@login_required
def dashboard():
    with get_db_connection() as connection:
        total_members = connection.execute(
            "SELECT COUNT(*) FROM members"
        ).fetchone()[0]
        active_members = connection.execute(
            "SELECT COUNT(*) FROM members WHERE status = ?", ("Active",)
        ).fetchone()[0]
        recent_members = connection.execute(
            "SELECT id, name, membership_plan, joining_date, status "
            "FROM members ORDER BY id DESC LIMIT 5"
        ).fetchall()
        active_member_rows = connection.execute(
            "SELECT * FROM members WHERE status = ? ORDER BY name",
            ("Active",),
        ).fetchall()
        due_soon_count = 0
        due_today_count = 0
        overdue_count = 0
        total_outstanding = 0
        for member in active_member_rows:
            fee_status = get_fee_info(connection, member)["fee_status"]
            due_soon_count += fee_status == "Due Soon"
            due_today_count += fee_status == "Due Today"
            overdue_count += fee_status == "Overdue"
            if fee_status in {"Due Today", "Overdue"}:
                total_outstanding += member["monthly_fee"]
        total_payments = connection.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM payments"
        ).fetchone()[0]
        recent_payments = connection.execute(
            """
            SELECT payments.id, payments.payment_date, payments.amount,
                   payments.payment_method, members.id AS member_id,
                   members.name AS member_name
            FROM payments JOIN members ON members.id = payments.member_id
            ORDER BY payments.payment_date DESC, payments.id DESC LIMIT 5
            """
        ).fetchall()
    return render_template(
        "dashboard.html",
        total_members=total_members,
        active_members=active_members,
        recent_members=recent_members,
        total_payments=total_payments,
        due_soon_count=due_soon_count,
        due_today_count=due_today_count,
        overdue_count=overdue_count,
        total_outstanding=total_outstanding,
        recent_payments=recent_payments,
    )
@app.route("/members")
@login_required
def members():
    search_query = request.args.get("q", "").strip()
    with get_db_connection() as connection:
        if search_query:
            search_pattern = f"%{search_query}%"
            member_list = connection.execute(
                """
                SELECT id, name, phone, membership_plan, monthly_fee, status
                FROM members
                WHERE name LIKE ? OR phone LIKE ? OR email LIKE ?
                    OR membership_plan LIKE ?
                ORDER BY id DESC
                """,
                (search_pattern, search_pattern, search_pattern, search_pattern),
            ).fetchall()
        else:
            member_list = connection.execute(
                "SELECT id, name, phone, membership_plan, monthly_fee, status "
                "FROM members ORDER BY id DESC"
            ).fetchall()
    return render_template(
        "members.html", members=member_list, search_query=search_query
    )
@app.route("/members/<int:member_id>")
@login_required
def member_profile(member_id):
    with get_db_connection() as connection:
        member = connection.execute(
            "SELECT * FROM members WHERE id = ?", (member_id,)
        ).fetchone()
        if member is None:
            return render_template("404.html"), 404
        payments = connection.execute(
            "SELECT * FROM payments WHERE member_id = ? "
            "ORDER BY payment_date DESC, id DESC",
            (member_id,),
        ).fetchall()
        total_paid = connection.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE member_id = ?",
            (member_id,),
        ).fetchone()[0]
        fee_info = get_fee_info(connection, member)
    return render_template(
        "member_profile.html",
        member=member,
        payments=payments,
        total_paid=total_paid,
        fee_info=fee_info,
    )
@app.route("/members/<int:member_id>/payments")
@login_required
def member_payment_history(member_id):
    with get_db_connection() as connection:
        member = connection.execute(
            "SELECT id, name FROM members WHERE id = ?", (member_id,)
        ).fetchone()
        if member is None:
            return render_template("404.html"), 404
        payments = connection.execute(
            "SELECT * FROM payments WHERE member_id = ? "
            "ORDER BY payment_date DESC, id DESC",
            (member_id,),
        ).fetchall()
    return render_template(
        "payment_history.html", member=member, payments=payments
    )
@app.route("/payments")
@login_required
def payments():
    receipt_id = request.args.get("receipt_id", type=int)
    with get_db_connection() as connection:
        payment_list = connection.execute(
            """
            SELECT payments.*, members.name AS member_name
            FROM payments JOIN members ON members.id = payments.member_id
            ORDER BY payments.payment_date DESC, payments.id DESC
            """
        ).fetchall()
        saved_payment = None
        if receipt_id is not None:
            saved_payment = connection.execute(
                "SELECT id FROM payments WHERE id = ?", (receipt_id,)
            ).fetchone()
    return render_template(
        "payments.html", payments=payment_list, saved_payment=saved_payment
    )
@app.route("/payments/<int:payment_id>/receipt")
@login_required
def payment_receipt(payment_id):
    with get_db_connection() as connection:
        payment = connection.execute(
            """
            SELECT payments.*
            FROM payments
            WHERE payments.id = ?
            """,
            (payment_id,),
        ).fetchone()
    if payment is None:
        return render_template("404.html"), 404
    return render_template(
        "payment_receipt.html", payment=payment, gym_name=GYM_NAME
    )
@app.route("/database/backup")
@login_required
def database_backup():
    try:
        with tempfile.TemporaryDirectory() as temporary_directory:
            backup_path = Path(temporary_directory) / "gym-management.db"
            with get_db_connection() as connection:
                backup_connection = sqlite3.connect(backup_path)
                try:
                    connection.backup(backup_connection)
                finally:
                    backup_connection.close()
            backup_data = backup_path.read_bytes()
    except (OSError, sqlite3.Error):
        app.logger.exception("Could not create database backup")
        flash("Database backup could not be created. Please try again.", "error")
        return redirect(url_for("dashboard"))
    return send_file(
        BytesIO(backup_data),
        as_attachment=True,
        download_name=f"gym-management-backup-{date.today().isoformat()}.db",
        mimetype="application/vnd.sqlite3",
        max_age=0,
    )
@app.route("/payments/add", methods=["GET", "POST"])
@login_required
def add_payment():
    with get_db_connection() as connection:
        member_list = connection.execute(
            "SELECT id, name, phone, monthly_fee, start_date, due_date "
            "FROM members ORDER BY name"
        ).fetchall()
    if request.method == "POST":
        submission_token = request.form.get("submission_token", "").strip()
        form_values = request.form
        pending_tokens = session.get("payment_submission_tokens", [])
        if not isinstance(pending_tokens, list):
            pending_tokens = []
        if submission_token not in pending_tokens:
            with get_db_connection() as connection:
                previous_payment = connection.execute(
                    "SELECT id FROM payments WHERE submission_token = ?",
                    (submission_token,),
                ).fetchone()
            if previous_payment is not None:
                return redirect(
                    url_for("payments", receipt_id=previous_payment["id"])
                )
            submission_token = secrets.token_urlsafe(32)
            pending_tokens = [*pending_tokens[-7:], submission_token]
            session["payment_submission_tokens"] = pending_tokens
            form_values = request.form.to_dict()
            form_values["submission_token"] = submission_token
            errors = ["This payment form expired. Review the details and submit again."]
        else:
            values, errors = validate_payment(request.form)
        if not errors:
            with get_db_connection() as connection:
                member_exists = connection.execute(
                    "SELECT id FROM members WHERE id = ?",
                    (values["member_id"],),
                ).fetchone()
            if member_exists is None:
                errors.append("The selected member does not exist.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "add_payment.html",
                members=member_list,
                form_values=form_values,
                payment_methods=PAYMENT_METHODS,
            )
        try:
            with get_db_connection() as connection:
                member = connection.execute(
                    "SELECT name, phone, membership_plan FROM members WHERE id = ?",
                    (values["member_id"],),
                ).fetchone()
                if member is None:
                    raise sqlite3.IntegrityError(
                        "Selected member no longer exists."
                    )
                connection.execute(
                    """
                    INSERT INTO payments (
                        member_id, payment_date, amount, payment_method,
                        transaction_id, notes, duration_months, start_date,
                        expiry_date, membership_plan, member_name, member_phone,
                        submission_token
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        values["member_id"], values["payment_date"],
                        values["amount"], values["payment_method"],
                        values["transaction_id"], values["notes"],
                        values["duration_months"], values["start_date"],
                        values["expiry_date"], member["membership_plan"],
                        member["name"], member["phone"], submission_token,
                    ),
                )
                payment_id = connection.execute(
                    "SELECT last_insert_rowid()"
                ).fetchone()[0]
                connection.execute(
                    "UPDATE members SET start_date = ?, due_date = ? WHERE id = ?",
                    (
                        values["start_date"], values["expiry_date"],
                        values["member_id"],
                    ),
                )
        except sqlite3.Error:
            with get_db_connection() as connection:
                previous_payment = connection.execute(
                    "SELECT id FROM payments WHERE submission_token = ?",
                    (submission_token,),
                ).fetchone()
            if previous_payment is not None:
                return redirect(
                    url_for("payments", receipt_id=previous_payment["id"])
                )
            app.logger.exception("Could not record payment")
            flash("Payment could not be recorded. Please try again.", "error")
            return render_template(
                "add_payment.html",
                members=member_list,
                form_values=form_values,
                payment_methods=PAYMENT_METHODS,
            ), 500
        with get_db_connection() as connection:
            paid_member = connection.execute(
                "SELECT * FROM members WHERE id = ?", (values["member_id"],)
            ).fetchone()
        if paid_member and paid_member["whatsapp_opt_in"]:
            payment_details = {
                "amount": f"{values['amount']:.2f}",
                "payment_date": values["payment_date"],
            }
            sent, detail = send_whatsapp_template(
                paid_member, "payment",
                [paid_member["name"], payment_details["amount"], payment_details["payment_date"]],
                dedupe_key=f"payment-{payment_id}",
            )
            if not sent:
                app.logger.warning("Payment saved but WhatsApp confirmation failed: %s", detail)

        session["payment_submission_tokens"] = [
            token for token in pending_tokens if token != submission_token
        ]
        flash("Payment recorded successfully.", "success")
        return redirect(url_for("payments", receipt_id=payment_id))
    submission_token = secrets.token_urlsafe(32)
    pending_tokens = session.get("payment_submission_tokens", [])
    if not isinstance(pending_tokens, list):
        pending_tokens = []
    session["payment_submission_tokens"] = [*pending_tokens[-7:], submission_token]
    return render_template(
        "add_payment.html",
        members=member_list,
        form_values={
            "submission_token": submission_token,
            "payment_date": date.today().isoformat(),
            "duration_months": "1",
            "start_date": date.today().isoformat(),
            "expiry_date": next_month(date.today()).isoformat(),
        },
        payment_methods=PAYMENT_METHODS,
    )
@app.route("/due-fees")
@login_required
def due_fees():
    filter_options = ("All", "Due Soon", "Due Today", "Overdue")
    status_filter = request.args.get("status", "All")
    if status_filter not in filter_options:
        status_filter = "All"
    due_members = []
    with get_db_connection() as connection:
        active_members = connection.execute(
            "SELECT * FROM members WHERE status = ? ORDER BY name", ("Active",)
        ).fetchall()
        for member in active_members:
            fee_info = get_fee_info(connection, member)
            due_member = {**dict(member), **fee_info}
            due_member["reminder_message"] = build_reminder_message(
                member, fee_info
            )
            if status_filter == "All" or fee_info["fee_status"] == status_filter:
                due_members.append(due_member)
    due_members.sort(key=lambda member: member["next_due_date"])
    return render_template(
        "due_fees.html",
        members=due_members,
        status_filter=status_filter,
        filter_options=filter_options,
    )
@app.route("/reminders")
@login_required
def reminder_center():
    today = date.today()
    reminders = []
    with get_db_connection() as connection:
        active_members = connection.execute(
            "SELECT id, name, phone, due_date FROM members "
            "WHERE status = ? ORDER BY due_date, name, id",
            ("Active",),
        ).fetchall()
    for member in active_members:
        days_remaining = (date.fromisoformat(member["due_date"]) - today).days
        reminder_status = get_reminder_status(days_remaining)
        if reminder_status is None:
            continue
        reminders.append({
            **dict(member),
            "days_remaining": days_remaining,
            "reminder_status": reminder_status,
            "reminder_message": build_membership_reminder_message(
                member, days_remaining
            ),
        })
    return render_template("reminder_center.html", reminders=reminders)
@app.route("/members/<int:member_id>/reminder", methods=["POST"])
@login_required
def send_reminder(member_id):
    with get_db_connection() as connection:
        member = connection.execute(
            "SELECT * FROM members WHERE id = ?", (member_id,)
        ).fetchone()
        if member is None:
            return render_template("404.html"), 404
        fee_info = get_fee_info(connection, member)
    if fee_info["fee_status"] == "Paid":
        flash("A reminder is only available when a fee is due or overdue.", "error")
    else:
        flash(f"Fee reminder prepared for {member['name']}.", "success")
    if request.form.get("return_to") == "profile":
        return redirect(url_for("member_profile", member_id=member_id))
    status_filter = request.form.get("status_filter", "All")
    if status_filter not in {"All", "Due Soon", "Due Today", "Overdue"}:
        status_filter = "All"
    return redirect(url_for("due_fees", status=status_filter))
@app.route("/members/add", methods=["GET", "POST"])
@login_required
def add_member():
    if request.method == "POST":
        values, errors = validate_member(request.form)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("add_member.html", form_values=request.form)
        try:
            with get_db_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO members (
                        name, phone, email, age, gender, joining_date,
                        membership_plan, monthly_fee, start_date, due_date,
                        status, notes, email_opt_in, whatsapp_opt_in
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        values["name"], values["phone"], values["email"],
                        values["age"], values["gender"], values["joining_date"],
                        values["membership_plan"], values["monthly_fee"],
                        values["start_date"], values["due_date"],
                        values["status"], values["notes"], values["email_opt_in"], values["whatsapp_opt_in"],
                    ),
                )
                member_id = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
        except sqlite3.Error:
            app.logger.exception("Could not save member")
            flash("Member could not be saved. Please try again.", "error")
            return render_template("add_member.html", form_values=request.form), 500
        if values["email_opt_in"]:
            with get_db_connection() as connection:
                new_member = connection.execute(
                    "SELECT * FROM members WHERE id = ?", (member_id,)
                ).fetchone()
            sent, detail = send_member_email(new_member, "welcome")
            if sent:
                flash("Welcome email sent.", "success")
            else:
                flash(f"Member saved, but welcome email was not sent: {detail}", "warning")
        if values["whatsapp_opt_in"]:
            with get_db_connection() as connection:
                new_member = connection.execute(
                    "SELECT * FROM members WHERE id = ?", (member_id,)
                ).fetchone()
            expiry = date.fromisoformat(new_member["due_date"]).strftime("%d %B %Y")
            sent, detail = send_whatsapp_template(
                new_member, "welcome", [new_member["name"], expiry]
            )
            if sent:
                flash("WhatsApp welcome message accepted by Meta.", "success")
            else:
                flash(f"Member saved, but WhatsApp welcome message was not sent: {detail}", "warning")
        flash("Member added successfully.", "success")
        return redirect(url_for("members"))
    return render_template("add_member.html", form_values={})
@app.route("/members/<int:member_id>/edit", methods=["GET", "POST"])
@login_required
def edit_member(member_id):
    with get_db_connection() as connection:
        member = connection.execute(
            "SELECT * FROM members WHERE id = ?", (member_id,)
        ).fetchone()
    if member is None:
        flash("Member not found.", "error")
        return redirect(url_for("members"))
    if request.method == "POST":
        values, errors = validate_member(request.form)
        if errors:
            for error in errors:
                flash(error, "error")
            form_values = request.form.to_dict()
            form_values["email_opt_in"] = str(values["email_opt_in"])
            return render_template(
                "edit_member.html", member=member, form_values=form_values
            )
        try:
            with get_db_connection() as connection:
                connection.execute(
                    """
                    UPDATE members SET
                        name = ?, phone = ?, email = ?, age = ?, gender = ?,
                        joining_date = ?, membership_plan = ?, monthly_fee = ?,
                        start_date = ?, due_date = ?, status = ?, notes = ?,
                        email_opt_in = ?, whatsapp_opt_in = ?
                    WHERE id = ?
                    """,
                    (
                        values["name"], values["phone"], values["email"],
                        values["age"], values["gender"], values["joining_date"],
                        values["membership_plan"], values["monthly_fee"],
                        values["start_date"], values["due_date"],
                        values["status"], values["notes"],
                        values["email_opt_in"], values["whatsapp_opt_in"], member_id,
                    ),
                )
        except sqlite3.Error:
            app.logger.exception("Could not update member %s", member_id)
            flash("Member could not be updated. Please try again.", "error")
            return render_template(
                "edit_member.html", member=member, form_values=request.form
            ), 500
        flash("Member details updated successfully.", "success")
        return redirect(url_for("members"))
    return render_template(
        "edit_member.html", member=member, form_values=dict(member)
    )
@app.route("/messages/logs")
@login_required
def message_logs():
    with get_db_connection() as connection:
        logs = connection.execute(
            "SELECT email_logs.*, members.name AS member_name "
            "FROM email_logs JOIN members ON members.id = email_logs.member_id "
            "ORDER BY email_logs.id DESC LIMIT 300"
        ).fetchall()
    return render_template(
        "message_logs.html", logs=logs, email_configured=email_is_configured()
    )
@app.route("/messages/logs/<int:log_id>/retry", methods=["POST"])
@login_required
def retry_message(log_id):
    with get_db_connection() as connection:
        log = connection.execute(
            "SELECT * FROM email_logs WHERE id = ?", (log_id,)
        ).fetchone()
        member = connection.execute(
            "SELECT * FROM members WHERE id = ?", (log["member_id"],)
        ).fetchone() if log else None
    if log is None or member is None:
        flash("Email log not found.", "error")
        return redirect(url_for("message_logs"))
    if log["status"] != "failed":
        flash("Only failed emails can be retried.", "error")
        return redirect(url_for("message_logs"))
    if not member["email_opt_in"] or not member["email"]:
        flash("Member has no email address or has not consented to email.", "error")
        return redirect(url_for("message_logs"))
    sent, detail = send_member_email(member, log["reminder_type"], force_retry=True)
    if sent:
        flash("Email accepted by the SMTP server.", "success")
    else:
        flash(f"Email retry failed: {detail}", "error")
    return redirect(url_for("message_logs"))
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register the first admin; existing admins can add further admins."""
    with get_db_connection() as connection:
        admin_count = connection.execute(
            "SELECT COUNT(*) FROM admins"
        ).fetchone()[0]
    # Public registration closes after the first admin is created.*
    if admin_count > 0 and "admin_id" not in session:
        flash("An admin account already exists. Please log in.", "error")
        return redirect(url_for("login"))
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []
        if not full_name or len(full_name) > 100:
            errors.append("Enter your name (maximum 100 characters).")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            errors.append(
                "Username must be 3–30 characters and contain only letters, "
                "numbers, dots, underscores or hyphens."
            )
        if len(email) > 254 or not re.fullmatch(
            r"[^\s@]+@[^\s@]+\.[^\s@]+", email
        ):
            errors.append("Enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must contain at least 8 characters.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("register.html", form_values=request.form)
        password_hash = generate_password_hash(password)
        try:
            with get_db_connection() as connection:
                # Acquire the SQLite write lock before rechecking the first-admin*
                # condition, preventing concurrent public registrations.*
                connection.execute("BEGIN IMMEDIATE")
                current_count = connection.execute(
                    "SELECT COUNT(*) FROM admins"
                ).fetchone()[0]
                if current_count > 0 and "admin_id" not in session:
                    flash("An admin account already exists. Please log in.", "error")
                    return redirect(url_for("login"))
                connection.execute(
                    """
                    INSERT INTO admins (full_name, username, email, password_hash)
                    VALUES (?, ?, ?, ?)
                    """,
                    (full_name, username, email, password_hash),
                )
        except sqlite3.IntegrityError:
            flash("That username or email is already registered.", "error")
            return render_template("register.html", form_values=request.form)
        if "admin_id" in session:
            flash("Admin account created successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Registration successful. Log in with your new account.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form_values={})
@app.route("/login", methods=["GET", "POST"])
def login():
    if "admin_id" in session:
        return redirect(url_for("dashboard"))
    next_url = request.values.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "error")
        else:
            with get_db_connection() as connection:
                admin = connection.execute(
                    "SELECT id, username, password_hash FROM admins "
                    "WHERE username = ?",
                    (username,),
                ).fetchone()
            if admin and check_password_hash(admin["password_hash"], password):
                session.clear()
                session["admin_id"] = admin["id"]
                session["admin_username"] = admin["username"]
                session.permanent = True
                if is_safe_redirect_target(next_url):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
    with get_db_connection() as connection:
        registration_open = (
            connection.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0
        )
    return render_template(
        "login.html",
        next_url=next_url,
        registration_open=registration_open,
    )

@app.route("/sw.js")
def service_worker():
    response = send_from_directory(
        app.static_folder,
        "sw.js",
        mimetype="application/javascript"
    )
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))
@app.errorhandler(404)
def page_not_found(_error):
    return render_template("404.html"), 404
if __name__ == "__main__":
    init_db()
    if email_is_configured():
        run_membership_reminders()
        start_reminder_scheduler()
        app.logger.info("Email membership reminder scheduler started.")
    else:
        app.logger.warning("Email SMTP is not configured; automatic email reminders are disabled.")
    if whatsapp_is_configured():
        run_whatsapp_membership_reminders()
        whatsapp_scheduler = BackgroundScheduler(timezone=app.config["MAIL_TIMEZONE"])
        whatsapp_scheduler.add_job(
            run_whatsapp_membership_reminders, trigger="interval", minutes=15,
            id="membership_whatsapp_reminders", replace_existing=True,
            max_instances=1, coalesce=True,
        )
        whatsapp_scheduler.start()
        atexit.register(lambda: whatsapp_scheduler.shutdown(wait=False) if whatsapp_scheduler.running else None)
        app.logger.info("WhatsApp membership reminder scheduler started.")
    else:
        app.logger.warning("WhatsApp Cloud API is not configured; automatic WhatsApp reminders are disabled.")
    app.run(host="0.0.0.0", port=5000, debug=False)
