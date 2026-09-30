"""Admin back-office (/admin): clients, quotes (devis), invoices
(factures), commercial licenses and support tickets. Admin-only; every view
is guarded by @admin_required. An uploaded PDF takes priority for a quote or
invoice; otherwise the PDF is generated on the fly.
"""

import os
import re
import secrets
import sqlite3

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort, send_file)
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from portal_db import get_db, now_iso, UPLOAD_DIR
from portal_auth import admin_required
import portal_billing as billing
import portal_pdf

admin_bp = Blueprint('admin', __name__, template_folder='../templates')

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# Per-kind settings for the two billing documents, which share one editor.
_DOCS = {
    'quote': {
        'table': 'quotes', 'prefix': 'DEV', 'noun': 'Devis', 'created': 'créé',
        'statuses': [('draft', 'Brouillon'), ('sent', 'Envoyé'),
                     ('accepted', 'Accepté'), ('declined', 'Refusé')],
        'default_status': 'draft', 'date_field': 'valid_until',
        'list_endpoint': 'admin.quotes', 'edit_endpoint': 'admin.quote_edit', 'id_arg': 'qid',
    },
    'invoice': {
        'table': 'invoices', 'prefix': 'FAC', 'noun': 'Facture', 'created': 'créée',
        'statuses': [('unpaid', 'Impayée'), ('paid', 'Payée'), ('cancelled', 'Annulée')],
        'default_status': 'unpaid', 'date_field': 'due_date',
        'list_endpoint': 'admin.invoices', 'edit_endpoint': 'admin.invoice_edit', 'id_arg': 'iid',
    },
}

_LICENSE_STATUSES = [('active', 'Active'), ('suspended', 'Suspendue'), ('revoked', 'Révoquée')]
_LICENSE_FILTERS = [('all', 'Toutes'), ('active', 'Actives'), ('renew', 'À renouveler'),
                    ('expired', 'Expirées'), ('inactive', 'Suspendues / révoquées')]


# --- Uploaded PDFs ----------------------------------------------------------

def _save_pdf(file_storage):
    """Store an uploaded PDF under UPLOAD_DIR with a random basename.
    Returns the basename to persist, or None if no valid file was sent."""
    if not file_storage or not file_storage.filename:
        return None
    name = secure_filename(file_storage.filename)
    head = file_storage.stream.read(5)
    file_storage.stream.seek(0)
    if not name.lower().endswith('.pdf') or head != b'%PDF-':
        flash("Fichier ignoré : seuls les PDF sont acceptés.", 'error')
        return None
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    basename = f"{secrets.token_hex(16)}.pdf"
    file_storage.save(os.path.join(UPLOAD_DIR, basename))
    return basename


def _upload_path(basename):
    """Absolute path of an uploaded file, or None if it would escape UPLOAD_DIR."""
    if not basename:
        return None
    full = os.path.realpath(os.path.join(UPLOAD_DIR, basename))
    if not full.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        return None
    return full


def _remove_upload(basename):
    full = _upload_path(basename)
    if full and os.path.isfile(full):
        os.remove(full)


def _send_pdf(row):
    full = _upload_path(row['pdf_path'])
    if not full or not os.path.isfile(full):
        abort(404)
    return send_file(full, as_attachment=True, download_name=f"{row['number']}.pdf")


# --- Shared lookups ---------------------------------------------------------

def _is_client(db, cid):
    return bool(cid) and db.execute(
        "SELECT 1 FROM users WHERE id = ? AND role = 'client'", (cid,)).fetchone() is not None


def _client_choices(include_id=None):
    """Active clients for a <select>, plus the record's current client even if
    it has since been deactivated."""
    return get_db().execute(
        "SELECT id, email, company, active FROM users WHERE role = 'client' "
        "AND (active = 1 OR id = ?) ORDER BY COALESCE(NULLIF(company, ''), email)",
        (include_id or 0,)).fetchall()


def _client_or_404(cid):
    row = get_db().execute("SELECT * FROM users WHERE id = ? AND role = 'client'", (cid,)).fetchone()
    if row is None:
        abort(404)
    return row


# --- Dashboard --------------------------------------------------------------

@admin_bp.route('/admin')
@admin_required
def dashboard():
    db = get_db()
    today = billing.today_iso()
    soon = billing.add_days(today, 30)
    unpaid = db.execute(
        "SELECT COUNT(*) n, COALESCE(SUM(amount_cents), 0) total FROM invoices WHERE status = 'unpaid'"
    ).fetchone()
    stats = {
        'clients': db.execute("SELECT COUNT(*) c FROM users WHERE role = 'client'").fetchone()['c'],
        'licenses_active': db.execute(
            "SELECT COUNT(*) c FROM licenses WHERE status = 'active' AND (end_date IS NULL OR end_date >= ?)",
            (today,)).fetchone()['c'],
        'invoices_unpaid': unpaid['n'],
        'unpaid_total': unpaid['total'],
        'tickets_open': db.execute("SELECT COUNT(*) c FROM tickets WHERE status != 'closed'").fetchone()['c'],
    }
    # Active licenses whose term or maintenance ends within 30 days (or already has).
    renewals = db.execute("""
        SELECT l.*, u.email, u.company FROM licenses l JOIN users u ON u.id = l.client_id
        WHERE l.status = 'active'
          AND ((l.end_date IS NOT NULL AND l.end_date <= ?)
               OR (l.maintenance_until IS NOT NULL AND l.maintenance_until <= ?))
        ORDER BY MIN(COALESCE(l.end_date, '9999'), COALESCE(l.maintenance_until, '9999'))
    """, (soon, soon)).fetchall()
    overdue = db.execute("""
        SELECT i.*, u.email, u.company FROM invoices i JOIN users u ON u.id = i.client_id
        WHERE i.status = 'unpaid' AND i.due_date IS NOT NULL AND i.due_date < ?
        ORDER BY i.due_date
    """, (today,)).fetchall()
    open_tickets = db.execute("""
        SELECT t.*, u.email, u.company FROM tickets t
        JOIN users u ON u.id = t.client_id
        WHERE t.status != 'closed' ORDER BY t.updated_at DESC LIMIT 10
    """).fetchall()
    return render_template('portal/admin/dashboard.html', stats=stats, renewals=renewals,
                           overdue=overdue, open_tickets=open_tickets, today=today)


# --- Clients ----------------------------------------------------------------

@admin_bp.route('/admin/clients')
@admin_required
def clients():
    rows = get_db().execute("""
        SELECT u.*, (SELECT COUNT(*) FROM licenses l
                     WHERE l.client_id = u.id AND l.status = 'active') AS license_count
        FROM users u WHERE u.role = 'client' ORDER BY u.created_at DESC
    """).fetchall()
    return render_template('portal/admin/clients.html', clients=rows)


@admin_bp.route('/admin/clients/new', methods=['POST'])
@admin_required
def client_new():
    f = request.form
    email = (f.get('email') or '').strip()
    password = f.get('password') or ''
    if not _EMAIL_RE.match(email):
        flash("Adresse e-mail invalide.", 'error')
        return redirect(url_for('admin.clients'))
    if len(password) < 8:
        flash("Le mot de passe doit faire au moins 8 caractères.", 'error')
        return redirect(url_for('admin.clients'))
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (email, password_hash, role, full_name, company, address, vat_number, created_at) "
            "VALUES (?,?,'client',?,?,?,?,?)",
            (email, generate_password_hash(password), (f.get('full_name') or '').strip(),
             (f.get('company') or '').strip(), (f.get('address') or '').strip(),
             (f.get('vat_number') or '').strip(), now_iso()))
        db.commit()
    except sqlite3.IntegrityError:
        flash("Un compte existe déjà avec cet e-mail.", 'error')
        return redirect(url_for('admin.clients'))
    flash(f"Client {email} créé.", 'ok')
    return redirect(url_for('admin.client_detail', cid=cur.lastrowid))


@admin_bp.route('/admin/clients/<int:cid>', methods=['GET', 'POST'])
@admin_required
def client_detail(cid):
    db = get_db()
    client = _client_or_404(cid)
    if request.method == 'POST':
        f = request.form
        email = (f.get('email') or '').strip()
        if not _EMAIL_RE.match(email):
            flash("Adresse e-mail invalide.", 'error')
            return redirect(url_for('admin.client_detail', cid=cid))
        try:
            db.execute(
                "UPDATE users SET email = ?, full_name = ?, company = ?, address = ?, vat_number = ? "
                "WHERE id = ?",
                (email, (f.get('full_name') or '').strip(), (f.get('company') or '').strip(),
                 (f.get('address') or '').strip(), (f.get('vat_number') or '').strip(), cid))
            db.commit()
            flash("Fiche client mise à jour.", 'ok')
        except sqlite3.IntegrityError:
            flash("Un autre compte utilise déjà cet e-mail.", 'error')
        return redirect(url_for('admin.client_detail', cid=cid))
    licenses = db.execute(
        "SELECT * FROM licenses WHERE client_id = ? ORDER BY start_date DESC", (cid,)).fetchall()
    quotes = db.execute(
        "SELECT * FROM quotes WHERE client_id = ? ORDER BY created_at DESC", (cid,)).fetchall()
    invoices = db.execute(
        "SELECT * FROM invoices WHERE client_id = ? ORDER BY issued_at DESC", (cid,)).fetchall()
    return render_template('portal/admin/client.html', client=client, licenses=licenses,
                           quotes=quotes, invoices=invoices, today=billing.today_iso())


@admin_bp.route('/admin/clients/<int:cid>/toggle', methods=['POST'])
@admin_required
def client_toggle(cid):
    row = _client_or_404(cid)
    db = get_db()
    db.execute("UPDATE users SET active = ? WHERE id = ?", (0 if row['active'] else 1, cid))
    db.commit()
    return redirect(url_for('admin.clients'))


@admin_bp.route('/admin/clients/<int:cid>/password', methods=['POST'])
@admin_required
def client_password(cid):
    _client_or_404(cid)
    password = request.form.get('password') or ''
    if len(password) < 8:
        flash("Le mot de passe doit faire au moins 8 caractères.", 'error')
        return redirect(url_for('admin.clients'))
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(password), cid))
    db.commit()
    flash("Mot de passe mis à jour.", 'ok')
    return redirect(url_for('admin.clients'))


# --- Quotes & invoices: shared editor ---------------------------------------

def _blank_doc(kind):
    cfg = _DOCS[kind]
    today = billing.today_iso()
    return {
        'id': None, 'client_id': request.args.get('client_id', type=int),
        'number': '', 'title': '', 'status': cfg['default_status'],
        'vat_rate': billing.DEFAULT_VAT, 'payment_terms': billing.DEFAULT_PAYMENT_TERMS,
        'notes': '', 'pdf_path': None, 'quote_id': None,
        'valid_until': billing.add_days(today, billing.QUOTE_VALIDITY_DAYS),
        'due_date': billing.add_days(today, billing.INVOICE_DUE_DAYS),
    }


def _render_doc_form(kind, doc, items, status_code=200):
    cfg = _DOCS[kind]
    db = get_db()
    extra = {}
    if doc.get('id'):
        if kind == 'quote':
            extra['linked_invoices'] = db.execute(
                "SELECT id, number, status FROM invoices WHERE quote_id = ? ORDER BY id",
                (doc['id'],)).fetchall()
        elif doc.get('quote_id'):
            extra['source_quote'] = db.execute(
                "SELECT id, number FROM quotes WHERE id = ?", (doc['quote_id'],)).fetchone()
    return render_template(
        'portal/admin/doc_form.html', kind=kind, cfg=cfg, doc=doc,
        items=items or [{'description': '', 'quantity': 1, 'unit_price_cents': None}],
        clients=_client_choices(doc.get('client_id')), presets=billing.ITEM_PRESETS,
        suggested_number=billing.next_number(db, cfg['table'], cfg['prefix']),
        **extra), status_code


def _doc_from_form(kind, existing):
    """Read and validate the editor. Returns (doc, items, errors); doc keeps
    what was typed so the form can be re-displayed on error."""
    cfg = _DOCS[kind]
    db = get_db()
    f = request.form
    doc = dict(existing) if existing else _blank_doc(kind)
    errors = []

    doc['client_id'] = f.get('client_id', type=int)
    doc['number'] = (f.get('number') or '').strip()[:40]
    doc['title'] = (f.get('title') or '').strip()[:200]
    doc['payment_terms'] = (f.get('payment_terms') or '').strip()[:2000]
    doc['notes'] = (f.get('notes') or '').strip()[:4000]

    status = f.get('status') or cfg['default_status']
    if status in dict(cfg['statuses']):
        doc['status'] = status
    else:
        errors.append("Statut invalide.")

    vat = billing.parse_vat(f.get('vat_rate'))
    if vat is None:
        errors.append("Taux de TVA invalide (entre 0 et 100).")
        doc['vat_rate'] = f.get('vat_rate')
    else:
        doc['vat_rate'] = vat

    raw_date = (f.get(cfg['date_field']) or '').strip()
    doc[cfg['date_field']] = billing.parse_date(raw_date)
    if raw_date and doc[cfg['date_field']] is None:
        errors.append("Date invalide.")

    items, item_errors = billing.parse_items(f)
    errors += item_errors
    if not _is_client(db, doc['client_id']):
        errors.append("Choisissez un client.")
    if not doc['title']:
        errors.append("L'objet est requis.")
    if not items and not item_errors:
        errors.append("Ajoutez au moins une ligne.")
    if doc['number']:
        dup = db.execute(f"SELECT 1 FROM {cfg['table']} WHERE number = ? AND id != ?",
                         (doc['number'], doc.get('id') or 0)).fetchone()
        if dup:
            errors.append(f"Le numéro {doc['number']} existe déjà.")
    return doc, items, errors


def _persist_doc(kind, doc, items, existing):
    cfg = _DOCS[kind]
    db = get_db()
    total = billing.totals(items, doc['vat_rate'])['ttc']
    if not doc['number']:
        doc['number'] = billing.next_number(db, cfg['table'], cfg['prefix'])

    pdf_path = existing['pdf_path'] if existing else None
    new_pdf = _save_pdf(request.files.get('pdf'))
    if new_pdf or request.form.get('remove_pdf'):
        _remove_upload(pdf_path)
        pdf_path = new_pdf

    common = (doc['client_id'], doc['number'], doc['title'], total, doc['status'],
              doc['vat_rate'], doc['payment_terms'], doc['notes'], pdf_path)
    if kind == 'quote':
        if existing:
            db.execute(
                "UPDATE quotes SET client_id = ?, number = ?, title = ?, amount_cents = ?, status = ?, "
                "vat_rate = ?, payment_terms = ?, notes = ?, pdf_path = ?, valid_until = ? WHERE id = ?",
                common + (doc['valid_until'], existing['id']))
            doc_id = existing['id']
        else:
            doc_id = db.execute(
                "INSERT INTO quotes (client_id, number, title, amount_cents, status, vat_rate, "
                "payment_terms, notes, pdf_path, valid_until, currency, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,'EUR',?)",
                common + (doc['valid_until'], now_iso())).lastrowid
    else:
        paid_at = None
        if doc['status'] == 'paid':
            paid_at = (existing['paid_at'] if existing else None) or now_iso()
        if existing:
            db.execute(
                "UPDATE invoices SET client_id = ?, number = ?, title = ?, amount_cents = ?, status = ?, "
                "vat_rate = ?, payment_terms = ?, notes = ?, pdf_path = ?, due_date = ?, paid_at = ? "
                "WHERE id = ?",
                common + (doc['due_date'], paid_at, existing['id']))
            doc_id = existing['id']
        else:
            doc_id = db.execute(
                "INSERT INTO invoices (client_id, number, title, amount_cents, status, vat_rate, "
                "payment_terms, notes, pdf_path, due_date, paid_at, currency, issued_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,'EUR',?)",
                common + (doc['due_date'], paid_at, now_iso())).lastrowid
    billing.save_items(db, kind, doc_id, items)
    db.commit()
    return doc_id


def _doc_create(kind):
    cfg = _DOCS[kind]
    if request.method == 'POST':
        doc, items, errors = _doc_from_form(kind, None)
        if errors:
            for e in errors:
                flash(e, 'error')
            return _render_doc_form(kind, doc, items, 400)
        doc_id = _persist_doc(kind, doc, items, None)
        flash(f"{cfg['noun']} {doc['number']} {cfg['created']}.", 'ok')
        return redirect(url_for(cfg['edit_endpoint'], **{cfg['id_arg']: doc_id}))
    return _render_doc_form(kind, _blank_doc(kind), [])


def _doc_edit(kind, doc_id):
    cfg = _DOCS[kind]
    db = get_db()
    row = db.execute(f"SELECT * FROM {cfg['table']} WHERE id = ?", (doc_id,)).fetchone()
    if row is None:
        abort(404)
    if request.method == 'POST':
        doc, items, errors = _doc_from_form(kind, row)
        if errors:
            for e in errors:
                flash(e, 'error')
            return _render_doc_form(kind, doc, items, 400)
        _persist_doc(kind, doc, items, row)
        flash("Modifications enregistrées.", 'ok')
        return redirect(url_for(cfg['edit_endpoint'], **{cfg['id_arg']: doc_id}))
    items = billing.items_for_display(row, billing.load_items(db, kind, doc_id))
    return _render_doc_form(kind, dict(row), items)


# --- Quotes (devis) ---------------------------------------------------------

@admin_bp.route('/admin/quotes')
@admin_required
def quotes():
    rows = get_db().execute("""
        SELECT q.*, u.email, u.company FROM quotes q
        JOIN users u ON u.id = q.client_id ORDER BY q.created_at DESC
    """).fetchall()
    return render_template('portal/admin/quotes.html', quotes=rows, today=billing.today_iso())


@admin_bp.route('/admin/quotes/new', methods=['GET', 'POST'])
@admin_required
def quote_new():
    return _doc_create('quote')


@admin_bp.route('/admin/quotes/<int:qid>', methods=['GET', 'POST'])
@admin_required
def quote_edit(qid):
    return _doc_edit('quote', qid)


@admin_bp.route('/admin/quotes/<int:qid>/status', methods=['POST'])
@admin_required
def quote_status(qid):
    status = request.form.get('status', '')
    if status not in dict(_DOCS['quote']['statuses']):
        abort(400)
    db = get_db()
    db.execute("UPDATE quotes SET status = ? WHERE id = ?", (status, qid))
    db.commit()
    return redirect(url_for('admin.quotes'))


@admin_bp.route('/admin/quotes/<int:qid>/delete', methods=['POST'])
@admin_required
def quote_delete(qid):
    db = get_db()
    row = db.execute("SELECT * FROM quotes WHERE id = ?", (qid,)).fetchone()
    if row is None:
        abort(404)
    if row['status'] != 'draft':
        flash("Seuls les devis au statut Brouillon peuvent être supprimés.", 'error')
        return redirect(url_for('admin.quote_edit', qid=qid))
    _remove_upload(row['pdf_path'])
    db.execute("DELETE FROM quotes WHERE id = ?", (qid,))
    db.commit()
    flash(f"Devis {row['number']} supprimé.", 'ok')
    return redirect(url_for('admin.quotes'))


@admin_bp.route('/admin/quotes/<int:qid>/invoice', methods=['POST'])
@admin_required
def quote_to_invoice(qid):
    """Create the invoice for a quote: same client, lines, VAT and terms."""
    db = get_db()
    q = db.execute("SELECT * FROM quotes WHERE id = ?", (qid,)).fetchone()
    if q is None:
        abort(404)
    items = billing.items_for_display(q, billing.load_items(db, 'quote', qid))
    number = billing.next_number(db, 'invoices', 'FAC')
    total = billing.totals(items, q['vat_rate'])['ttc']
    iid = db.execute(
        "INSERT INTO invoices (client_id, number, title, amount_cents, currency, status, issued_at, "
        "vat_rate, due_date, payment_terms, notes, quote_id) VALUES (?,?,?,?,?,'unpaid',?,?,?,?,?,?)",
        (q['client_id'], number, q['title'], total, q['currency'], now_iso(), q['vat_rate'],
         billing.add_days(billing.today_iso(), billing.INVOICE_DUE_DAYS),
         q['payment_terms'], q['notes'], qid)).lastrowid
    billing.save_items(db, 'invoice', iid, items)
    if q['status'] != 'accepted':
        db.execute("UPDATE quotes SET status = 'accepted' WHERE id = ?", (qid,))
    db.commit()
    flash(f"Facture {number} créée à partir du devis {q['number']}.", 'ok')
    return redirect(url_for('admin.invoice_edit', iid=iid))


@admin_bp.route('/admin/quotes/<int:qid>/pdf')
@admin_required
def quote_pdf(qid):
    db = get_db()
    row = db.execute("SELECT * FROM quotes WHERE id = ?", (qid,)).fetchone()
    if row is None:
        abort(404)
    if row['pdf_path'] and not request.args.get('generated'):
        return _send_pdf(row)
    client = db.execute("SELECT * FROM users WHERE id = ?", (row['client_id'],)).fetchone()
    pdf = portal_pdf.build_quote_pdf(row, client, billing.load_items(db, 'quote', qid))
    return portal_pdf.as_response(pdf, f"{row['number']}.pdf")


# --- Invoices (facturation) -------------------------------------------------

@admin_bp.route('/admin/invoices')
@admin_required
def invoices():
    rows = get_db().execute("""
        SELECT i.*, u.email, u.company FROM invoices i
        JOIN users u ON u.id = i.client_id ORDER BY i.issued_at DESC
    """).fetchall()
    return render_template('portal/admin/invoices.html', invoices=rows, today=billing.today_iso())


@admin_bp.route('/admin/invoices/new', methods=['GET', 'POST'])
@admin_required
def invoice_new():
    return _doc_create('invoice')


@admin_bp.route('/admin/invoices/<int:iid>', methods=['GET', 'POST'])
@admin_required
def invoice_edit(iid):
    return _doc_edit('invoice', iid)


@admin_bp.route('/admin/invoices/<int:iid>/status', methods=['POST'])
@admin_required
def invoice_status(iid):
    status = request.form.get('status', '')
    if status not in dict(_DOCS['invoice']['statuses']):
        abort(400)
    db = get_db()
    if status == 'paid':
        # Keep the original payment date if it was already marked paid.
        db.execute("UPDATE invoices SET status = 'paid', paid_at = COALESCE(paid_at, ?) WHERE id = ?",
                   (now_iso(), iid))
    else:
        db.execute("UPDATE invoices SET status = ?, paid_at = NULL WHERE id = ?", (status, iid))
    db.commit()
    return redirect(url_for('admin.invoices'))


@admin_bp.route('/admin/invoices/<int:iid>/pdf')
@admin_required
def invoice_pdf(iid):
    db = get_db()
    row = db.execute("SELECT * FROM invoices WHERE id = ?", (iid,)).fetchone()
    if row is None:
        abort(404)
    if row['pdf_path'] and not request.args.get('generated'):
        return _send_pdf(row)
    client = db.execute("SELECT * FROM users WHERE id = ?", (row['client_id'],)).fetchone()
    quote = db.execute("SELECT number FROM quotes WHERE id = ?", (row['quote_id'],)).fetchone() \
        if row['quote_id'] else None
    pdf = portal_pdf.build_invoice_pdf(row, client, billing.load_items(db, 'invoice', iid),
                                       quote['number'] if quote else None)
    return portal_pdf.as_response(pdf, f"{row['number']}.pdf")


# --- Licenses ---------------------------------------------------------------

@admin_bp.route('/admin/licenses')
@admin_required
def licenses():
    flt = request.args.get('filter', 'all')
    if flt not in dict(_LICENSE_FILTERS):
        flt = 'all'
    today = billing.today_iso()
    soon = billing.add_days(today, 30)
    rows = []
    for r in get_db().execute("""
        SELECT l.*, u.email, u.company FROM licenses l JOIN users u ON u.id = l.client_id
        ORDER BY l.created_at DESC
    """):
        state = billing.license_state(r, today)
        renew = r['status'] == 'active' and (
            (r['end_date'] and r['end_date'] <= soon)
            or billing.maintenance_state(r, today) in ('soon', 'expired'))
        if (flt == 'all'
                or (flt == 'active' and state == 'active')
                or (flt == 'renew' and renew)
                or (flt == 'expired' and state == 'expired')
                or (flt == 'inactive' and state in ('suspended', 'revoked'))):
            rows.append(r)
    return render_template('portal/admin/licenses.html', licenses=rows, filter=flt,
                           filters=_LICENSE_FILTERS, today=today)


def _blank_license():
    today = billing.today_iso()
    return {
        'id': None, 'license_key': None, 'client_id': request.args.get('client_id', type=int),
        'tier': 'startup', 'product': 'tcpcat', 'seats': 1, 'start_date': today,
        'end_date': billing.add_years(today, 1), 'maintenance_until': billing.add_years(today, 1),
        'status': 'active', 'notes': '', 'invoice_id': request.args.get('invoice_id', type=int),
    }


def _render_license_form(lic, status_code=200):
    invoices = get_db().execute("""
        SELECT i.id, i.number, i.client_id, u.company, u.email FROM invoices i
        JOIN users u ON u.id = i.client_id ORDER BY i.issued_at DESC LIMIT 300
    """).fetchall()
    return render_template(
        'portal/admin/license_form.html', lic=lic, clients=_client_choices(lic.get('client_id')),
        tiers=billing.LICENSE_TIERS, statuses=_LICENSE_STATUSES, invoices=invoices), status_code


def _license_from_form(existing):
    f = request.form
    db = get_db()
    lic = dict(existing) if existing else _blank_license()
    errors = []

    lic['client_id'] = f.get('client_id', type=int)
    lic['tier'] = f.get('tier')
    lic['product'] = (f.get('product') or '').strip()[:80] or 'tcpcat'
    lic['notes'] = (f.get('notes') or '').strip()[:2000]
    lic['invoice_id'] = f.get('invoice_id', type=int) or None
    if existing:
        lic['status'] = f.get('status', existing['status'])

    seats = f.get('seats', type=int)
    if seats is None or not 1 <= seats <= 100000:
        errors.append("Nombre de produits / appliances invalide.")
        lic['seats'] = f.get('seats')
    else:
        lic['seats'] = seats

    for field, label in (('start_date', 'début'), ('end_date', 'fin'),
                         ('maintenance_until', 'fin de maintenance')):
        raw = (f.get(field) or '').strip()
        lic[field] = billing.parse_date(raw)
        if raw and lic[field] is None:
            errors.append(f"Date de {label} invalide.")

    if not _is_client(db, lic['client_id']):
        errors.append("Choisissez un client.")
    if lic['tier'] not in billing.LICENSE_TIERS:
        errors.append("Formule invalide.")
    if lic['status'] not in dict(_LICENSE_STATUSES):
        errors.append("Statut invalide.")
    if not lic['start_date']:
        errors.append("La date de début est requise.")
    elif lic['end_date'] and lic['end_date'] < lic['start_date']:
        errors.append("La date de fin précède la date de début.")
    if lic['invoice_id']:
        inv = db.execute("SELECT client_id FROM invoices WHERE id = ?", (lic['invoice_id'],)).fetchone()
        if inv is None or inv['client_id'] != lic['client_id']:
            errors.append("La facture liée doit appartenir au même client.")
    return lic, errors


@admin_bp.route('/admin/licenses/new', methods=['GET', 'POST'])
@admin_required
def license_new():
    if request.method == 'POST':
        lic, errors = _license_from_form(None)
        if errors:
            for e in errors:
                flash(e, 'error')
            return _render_license_form(lic, 400)
        db = get_db()
        key = billing.generate_license_key(db)
        lid = db.execute(
            "INSERT INTO licenses (client_id, license_key, product, tier, seats, start_date, end_date, "
            "maintenance_until, status, notes, invoice_id, created_at) VALUES (?,?,?,?,?,?,?,?,'active',?,?,?)",
            (lic['client_id'], key, lic['product'], lic['tier'], lic['seats'], lic['start_date'],
             lic['end_date'], lic['maintenance_until'], lic['notes'], lic['invoice_id'], now_iso())
        ).lastrowid
        db.commit()
        flash(f"Licence {key} créée.", 'ok')
        return redirect(url_for('admin.license_edit', lid=lid))
    return _render_license_form(_blank_license())


@admin_bp.route('/admin/licenses/<int:lid>', methods=['GET', 'POST'])
@admin_required
def license_edit(lid):
    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE id = ?", (lid,)).fetchone()
    if row is None:
        abort(404)
    if request.method == 'POST':
        lic, errors = _license_from_form(row)
        if errors:
            for e in errors:
                flash(e, 'error')
            return _render_license_form(lic, 400)
        db.execute(
            "UPDATE licenses SET client_id = ?, product = ?, tier = ?, seats = ?, start_date = ?, "
            "end_date = ?, maintenance_until = ?, status = ?, notes = ?, invoice_id = ? WHERE id = ?",
            (lic['client_id'], lic['product'], lic['tier'], lic['seats'], lic['start_date'],
             lic['end_date'], lic['maintenance_until'], lic['status'], lic['notes'],
             lic['invoice_id'], lid))
        db.commit()
        flash("Licence mise à jour.", 'ok')
        return redirect(url_for('admin.license_edit', lid=lid))
    return _render_license_form(dict(row))


@admin_bp.route('/admin/licenses/<int:lid>/renew', methods=['POST'])
@admin_required
def license_renew(lid):
    """Extend the term and/or maintenance by one year, from the current end
    date if still running, otherwise from today."""
    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE id = ?", (lid,)).fetchone()
    if row is None:
        abort(404)
    today = billing.today_iso()
    end, maint = row['end_date'], row['maintenance_until']
    if not end and not maint:
        flash("Licence perpétuelle sans maintenance : rien à renouveler.", 'error')
        return redirect(url_for('admin.license_edit', lid=lid))
    new_end = billing.add_years(max(end, today), 1) if end else None
    new_maint = billing.add_years(max(maint, today), 1) if maint else None
    db.execute("UPDATE licenses SET end_date = ?, maintenance_until = ? WHERE id = ?",
               (new_end, new_maint, lid))
    db.commit()
    parts = []
    if new_end:
        parts.append(f"licence jusqu'au {billing.fmt_date(new_end)}")
    if new_maint:
        parts.append(f"maintenance jusqu'au {billing.fmt_date(new_maint)}")
    flash("Renouvelée : " + ", ".join(parts) + ".", 'ok')
    return redirect(url_for('admin.license_edit', lid=lid))


@admin_bp.route('/admin/licenses/<int:lid>/pdf')
@admin_required
def license_pdf(lid):
    db = get_db()
    row = db.execute("SELECT * FROM licenses WHERE id = ?", (lid,)).fetchone()
    if row is None:
        abort(404)
    client = db.execute("SELECT * FROM users WHERE id = ?", (row['client_id'],)).fetchone()
    return portal_pdf.as_response(portal_pdf.build_license_pdf(row, client),
                                  f"licence-{row['license_key']}.pdf")


# --- Tickets ----------------------------------------------------------------

@admin_bp.route('/admin/tickets')
@admin_required
def tickets():
    rows = get_db().execute("""
        SELECT t.*, u.email, u.company,
               (SELECT COUNT(*) FROM ticket_messages m WHERE m.ticket_id = t.id) AS msg_count
        FROM tickets t JOIN users u ON u.id = t.client_id
        ORDER BY CASE t.status WHEN 'closed' THEN 1 ELSE 0 END, t.updated_at DESC
    """).fetchall()
    return render_template('portal/admin/tickets.html', tickets=rows)


@admin_bp.route('/admin/tickets/<int:tid>', methods=['GET', 'POST'])
@admin_required
def ticket_view(tid):
    db = get_db()
    ticket = db.execute("""
        SELECT t.*, u.email, u.company FROM tickets t
        JOIN users u ON u.id = t.client_id WHERE t.id = ?
    """, (tid,)).fetchone()
    if ticket is None:
        abort(404)
    if request.method == 'POST':
        body = (request.form.get('body') or '').strip()
        new_status = request.form.get('status')
        ts = now_iso()
        if body:
            db.execute(
                "INSERT INTO ticket_messages (ticket_id, author_role, body, created_at) VALUES (?,?,?,?)",
                (tid, 'admin', body, ts))
            db.execute("UPDATE tickets SET status = 'pending', updated_at = ? WHERE id = ?", (ts, tid))
        if new_status in ('open', 'pending', 'closed'):
            db.execute("UPDATE tickets SET status = ?, updated_at = ? WHERE id = ?", (new_status, ts, tid))
        db.commit()
        return redirect(url_for('admin.ticket_view', tid=tid))
    messages = db.execute(
        "SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at", (tid,)).fetchall()
    return render_template('portal/admin/ticket.html', ticket=ticket, messages=messages)
