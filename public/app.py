import os

from flask import Flask, Response, render_template, url_for


import routes.release as release
import routes.notice as notice
import routes.internals as internals
import routes.oem as oem

app = Flask(__name__, template_folder='templates')

app.register_blueprint(release.release_bp)
app.register_blueprint(notice.notice_bp)
app.register_blueprint(internals.internals_bp)
app.register_blueprint(oem.oem_bp)

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
