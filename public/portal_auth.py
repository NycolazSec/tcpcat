"""Session auth, access-control decorators, and CSRF protection for the
tcpcat portal. Session-based (signed cookie), passwords hashed with
werkzeug. Kept dependency-free beyond Flask/werkzeug on purpose.
"""

import functools
import hmac
import secrets

from flask import g, redirect, request, session, url_for, abort, flash

from portal_db import get_db


def current_user():
    """The logged-in user row (or None), cached on g for the request."""
    if 'user' not in g:
        g.user = None
        uid = session.get('uid')
        if uid is not None:
            row = get_db().execute(
                'SELECT * FROM users WHERE id = ? AND active = 1', (uid,)
            ).fetchone()
            g.user = row
    return g.user


def login_user(user_row):
    # Rotate the session id on privilege change to avoid session fixation.
    session.clear()
    session['uid'] = user_row['id']
    session['role'] = user_row['role']
    session.permanent = True


def logout_user():
    session.clear()


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for('auth.login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for('auth.login', next=request.path))
        if user['role'] != 'admin':
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def client_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for('auth.login', next=request.path))
        if user['role'] != 'client':
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# --- CSRF -------------------------------------------------------------------
# A per-session random token, echoed in a hidden field on every POST form and
# verified here. Constant-time comparison; state-changing requests only.

def csrf_token():
    tok = session.get('csrf')
    if not tok:
        tok = secrets.token_urlsafe(32)
        session['csrf'] = tok
    return tok


def verify_csrf():
    sent = request.form.get('csrf_token', '')
    good = session.get('csrf', '')
    if not good or not hmac.compare_digest(sent, good):
        abort(400, description='Invalid or missing CSRF token.')


def init_app(app):
    # Make csrf_token() available to every template.
    app.jinja_env.globals['csrf_token'] = csrf_token
    app.jinja_env.globals['current_user'] = current_user

    @app.before_request
    def _csrf_protect():
        if request.method == 'POST':
            verify_csrf()
