from flask import Blueprint, render_template, request, redirect, url_for, flash
from werkzeug.security import check_password_hash

from portal_db import get_db
from portal_auth import login_user, logout_user, current_user

auth_bp = Blueprint('auth', __name__, template_folder='../templates')


def _safe_next(target):
    # Only allow same-site relative redirects (no scheme/host), to avoid an
    # open redirect through ?next=.
    if target and target.startswith('/') and not target.startswith('//'):
        return target
    return None


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    user = current_user()
    if user is not None:
        return redirect(url_for('admin.dashboard' if user['role'] == 'admin' else 'portal.dashboard'))

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''
        row = get_db().execute(
            'SELECT * FROM users WHERE email = ? AND active = 1', (email,)
        ).fetchone()
        # Always run a hash check shape even on unknown user is overkill here;
        # a simple check with a generic error avoids leaking which part failed.
        if row is not None and check_password_hash(row['password_hash'], password):
            login_user(row)
            dest = _safe_next(request.form.get('next')) or (
                url_for('admin.dashboard') if row['role'] == 'admin' else url_for('portal.dashboard'))
            return redirect(dest)
        flash("Identifiants invalides.", 'error')

    return render_template('portal/login.html', next=_safe_next(request.args.get('next')) or '')


@auth_bp.route('/logout', methods=['POST'])
def logout():
    logout_user()
    flash("Vous êtes déconnecté.", 'ok')
    return redirect(url_for('auth.login'))
