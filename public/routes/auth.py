"""Login / logout, with optional e-mail two-factor authentication.

When PORTAL_2FA=1, a correct e-mail + password does not log the user in
directly: a 6-digit code is e-mailed and must be entered on /login/verify.
The code is stored *hashed* in the (signed) session with a short expiry and a
capped number of attempts.
"""

import logging
import os
import secrets
import time

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, session)
from werkzeug.security import check_password_hash, generate_password_hash

from portal_db import get_db
from portal_auth import login_user, logout_user, current_user
import portal_mail

log = logging.getLogger('portal.auth')

auth_bp = Blueprint('auth', __name__, template_folder='../templates')

TWO_FA = os.environ.get('PORTAL_2FA') == '1'
CODE_TTL = 10 * 60          # seconds a code stays valid
MAX_ATTEMPTS = 5


def _safe_next(target):
    # Only allow same-site relative redirects (no scheme/host), to avoid an
    # open redirect through ?next=.
    if target and target.startswith('/') and not target.startswith('//'):
        return target
    return None


def _dest_for(role, nxt):
    return nxt or (url_for('admin.dashboard') if role == 'admin' else url_for('portal.dashboard'))


def _start_2fa(user_row, nxt):
    """Generate, store (hashed) and send a login code. Returns the masked
    destination address for display."""
    code = f"{secrets.randbelow(1_000_000):06d}"
    session['2fa_uid'] = user_row['id']
    session['2fa_hash'] = generate_password_hash(code)
    session['2fa_exp'] = time.time() + CODE_TTL
    session['2fa_tries'] = 0
    session['2fa_next'] = nxt or ''
    body = (
        "Bonjour,\n\n"
        f"Votre code de connexion tcpcat est : {code}\n\n"
        f"Il est valable {CODE_TTL // 60} minutes. Si vous n'avez pas tenté de "
        "vous connecter, ignorez cet e-mail.\n\n"
        "-- tcpcat"
    )
    sent = portal_mail.send(user_row['email'], "Votre code de connexion tcpcat", body)
    if not sent:
        # No SMTP configured (dev): log the code so the flow is testable.
        # Never do this in production -- configure SMTP_* instead.
        log.warning("2FA code for %s (SMTP not configured): %s", user_row['email'], code)
    return user_row['email']


def _mask(email):
    name, _, domain = email.partition('@')
    shown = name[0] + '***' if name else '***'
    return f"{shown}@{domain}"


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    user = current_user()
    if user is not None:
        return redirect(_dest_for(user['role'], None))

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        nxt = _safe_next(request.form.get('next'))
        row = get_db().execute(
            'SELECT * FROM users WHERE email = ? AND active = 1', (email,)
        ).fetchone()
        if row is not None and check_password_hash(row['password_hash'], password):
            if TWO_FA:
                dest_email = _start_2fa(row, nxt)
                flash(f"Un code de connexion a été envoyé à {_mask(dest_email)}.", 'ok')
                return redirect(url_for('auth.verify'))
            login_user(row)
            return redirect(_dest_for(row['role'], nxt))
        flash("Identifiants invalides.", 'error')

    return render_template('portal/login.html', next=_safe_next(request.args.get('next')) or '')


@auth_bp.route('/login/verify', methods=['GET', 'POST'])
def verify():
    uid = session.get('2fa_uid')
    if not uid:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        # Resend a fresh code.
        if request.form.get('action') == 'resend':
            row = get_db().execute('SELECT * FROM users WHERE id = ? AND active = 1', (uid,)).fetchone()
            if row is not None:
                dest = _start_2fa(row, session.get('2fa_next'))
                flash(f"Nouveau code envoyé à {_mask(dest)}.", 'ok')
            return redirect(url_for('auth.verify'))

        # Expiry / attempt guards.
        if time.time() > session.get('2fa_exp', 0):
            _clear_2fa()
            flash("Code expiré, veuillez vous reconnecter.", 'error')
            return redirect(url_for('auth.login'))
        if session.get('2fa_tries', 0) >= MAX_ATTEMPTS:
            _clear_2fa()
            flash("Trop de tentatives, veuillez vous reconnecter.", 'error')
            return redirect(url_for('auth.login'))

        code = (request.form.get('code') or '').strip()
        if check_password_hash(session.get('2fa_hash', ''), code):
            row = get_db().execute('SELECT * FROM users WHERE id = ? AND active = 1', (uid,)).fetchone()
            nxt = _safe_next(session.get('2fa_next'))
            if row is None:
                _clear_2fa()
                flash("Compte indisponible.", 'error')
                return redirect(url_for('auth.login'))
            login_user(row)  # clears the session, including the 2FA fields
            return redirect(_dest_for(row['role'], nxt))
        session['2fa_tries'] = session.get('2fa_tries', 0) + 1
        flash("Code incorrect.", 'error')

    return render_template('portal/verify.html')


def _clear_2fa():
    for k in ('2fa_uid', '2fa_hash', '2fa_exp', '2fa_tries', '2fa_next'):
        session.pop(k, None)


@auth_bp.route('/logout', methods=['POST'])
def logout():
    logout_user()
    flash("Vous êtes déconnecté.", 'ok')
    return redirect(url_for('auth.login'))
