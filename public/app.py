import os
import secrets
from datetime import timedelta

import click
from flask import Flask, Response, render_template, url_for

import routes.release as release
import routes.notice as notice
import routes.internals as internals
import routes.oem as oem

app = Flask(__name__, template_folder='templates')

# --- Public marketing site --------------------------------------------------
app.register_blueprint(release.release_bp)
app.register_blueprint(notice.notice_bp)
app.register_blueprint(internals.internals_bp)
app.register_blueprint(oem.oem_bp)

# --- Client portal + admin back-office (opt-in) -----------------------------
# The portal exposes a login/admin/pro surface, so it is NOT part of the public
# tcpcat.io deployment. It is registered ONLY when PORTAL_ENABLED=1, i.e. on a
# separate/internal instance. Deploying the marketing site (without the flag)
# ships no login page and no /admin or /pro routes at all.
PORTAL_ENABLED = os.environ.get('PORTAL_ENABLED') == '1'

if PORTAL_ENABLED:
    import portal_db
    import portal_auth
    import routes.auth as auth
    import routes.admin as admin
    import routes.portal as portal

    # SECRET_KEY signs the session cookie. Required for the portal; set it in
    # the environment. A random dev fallback keeps local runs working (sessions
    # reset on restart).
    app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        # Only send the cookie over HTTPS in production (set PORTAL_SECURE_COOKIES=1
        # behind the TLS-terminating proxy). Off by default so local http works.
        SESSION_COOKIE_SECURE=os.environ.get('PORTAL_SECURE_COOKIES') == '1',
        PERMANENT_SESSION_LIFETIME=timedelta(days=14),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # cap PDF uploads at 10 MB
    )

    portal_db.init_app(app)
    portal_auth.init_app(app)
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(admin.admin_bp)
    app.register_blueprint(portal.portal_bp)

    # --- CLI: database + admin bootstrap (portal only) ----------------------
    @app.cli.command('init-db')
    def init_db_command():
        """Create the SQLite schema and upload directory."""
        portal_db.init_db()
        click.echo(f"Base initialisée : {portal_db.DB_PATH}")

    @app.cli.command('create-admin')
    @click.option('--email', prompt=True)
    @click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin_command(email, password):
        """Create (or promote) an administrator account."""
        from werkzeug.security import generate_password_hash
        portal_db.init_db()
        conn = portal_db.sqlite3.connect(portal_db.DB_PATH)
        try:
            conn.execute('PRAGMA foreign_keys = ON')
            existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
            pw = generate_password_hash(password)
            if existing:
                conn.execute("UPDATE users SET password_hash = ?, role = 'admin', active = 1 WHERE id = ?",
                             (pw, existing[0]))
                click.echo(f"Compte {email} mis à jour en administrateur.")
            else:
                conn.execute(
                    "INSERT INTO users (email, password_hash, role, created_at) VALUES (?,?,'admin',?)",
                    (email, pw, portal_db.now_iso()))
                click.echo(f"Administrateur {email} créé.")
            conn.commit()
        finally:
            conn.close()


_STATUS_FR = {
    'draft': 'Brouillon', 'sent': 'Envoyé', 'accepted': 'Accepté', 'declined': 'Refusé',
    'unpaid': 'Impayée', 'paid': 'Payée', 'cancelled': 'Annulée',
    'open': 'Ouvert', 'pending': 'En attente', 'closed': 'Clôturé',
}


@app.template_filter('euros')
def euros(cents, currency='EUR'):
    """Format integer cents as French currency, e.g. 398000 -> '3 980,00 €'."""
    amount = (cents or 0) / 100
    body = f"{amount:,.2f}".replace(',', ' ').replace('.', ',')
    return f"{body} €" if currency == 'EUR' else f"{body} {currency}"


@app.context_processor
def inject_portal_helpers():
    return {'status_fr': lambda s: _STATUS_FR.get(s, s)}


# Public origin used for absolute URLs (canonical links, Open Graph image,
# sitemap). Not derived from the request: behind a reverse proxy the app
# sees its internal host and plain http, which social crawlers can't use.
SITE_URL = os.environ.get('SITE_URL', 'https://tcpcat.io').rstrip('/')

INDEXED_ENDPOINTS = ['undex', 'internals.internals', 'release.release', 'notice.notice', 'oem.oem']


@app.context_processor
def inject_site_url():
    return {'site_url': SITE_URL}


@app.route('/')
def undex():
    return render_template('index.html', active='home')


@app.route('/robots.txt')
def robots_txt():
    body = f"User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}/sitemap.xml\n"
    return Response(body, mimetype='text/plain')


@app.route('/sitemap.xml')
def sitemap_xml():
    urls = ''.join(f"  <url><loc>{SITE_URL}{url_for(endpoint)}</loc></url>\n" for endpoint in INDEXED_ENDPOINTS)
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f'{urls}'
        '</urlset>\n'
    )
    return Response(body, mimetype='application/xml')


@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run()
