"""Minimal SMTP e-mail sending for the portal (stdlib only).

Configured via environment:
    SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD,
    SMTP_FROM (default: SMTP_USER), SMTP_TLS ('1' STARTTLS default, '0' off),
    SMTP_SSL ('1' for implicit TLS / port 465).

If SMTP is not configured, send() returns False and the caller decides what to
do (in dev we log the 2FA code instead of emailing it).
"""

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage

log = logging.getLogger('portal.mail')

SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
SMTP_FROM = os.environ.get('SMTP_FROM') or SMTP_USER or 'no-reply@tcpcat.io'
SMTP_TLS = os.environ.get('SMTP_TLS', '1') == '1'
SMTP_SSL = os.environ.get('SMTP_SSL', '0') == '1'


def is_configured():
    return bool(SMTP_HOST)


def send(to_addr, subject, body):
    """Send a plain-text e-mail. Returns True on success, False otherwise."""
    if not is_configured():
        return False
    msg = EmailMessage()
    msg['From'] = SMTP_FROM
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.set_content(body)
    try:
        if SMTP_SSL:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=15) as s:
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                if SMTP_TLS:
                    s.starttls(context=ssl.create_default_context())
                if SMTP_USER:
                    s.login(SMTP_USER, SMTP_PASSWORD)
                s.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 - log and degrade gracefully
        log.error("SMTP send failed: %s", exc)
        return False
