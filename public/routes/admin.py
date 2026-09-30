"""Admin back-office (/admin): manage clients, quotes (devis), invoices
(facturation) and support tickets. Admin-only; every view is guarded by
@admin_required. PDFs are uploaded here and stored under UPLOAD_DIR.
"""

import os
import re
import secrets

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort, send_file)
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from portal_db import get_db, now_iso, UPLOAD_DIR
from portal_auth import admin_required

admin_bp = Blueprint('admin', __name__, template_folder='../templates')


def _parse_amount(raw):
    """Turn a user-entered amount ('1234,56' or '1234.56') into integer cents."""
    raw = (raw or '').strip().replace(' ', '').replace(',', '.')
    if not raw:
        return 0
    try:
        return int(round(float(raw) * 100))
    except ValueError:
        return 0


def _save_pdf(file_storage):
    """Store an uploaded PDF under UPLOAD_DIR with a random basename.
    Returns the basename to persist, or None if no valid file was sent."""
    if not file_storage or not file_storage.filename:
        return None
    name = secure_filename(file_storage.filename)
    if not name.lower().endswith('.pdf'):
        flash("Seuls les fichiers PDF sont acceptés.", 'error')
        return None
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    basename = f"{secrets.token_hex(16)}.pdf"
    file_storage.save(os.path.join(UPLOAD_DIR, basename))
    return basename


def _send_pdf(row):
    if not row or not row['pdf_path']:
        abort(404)
    full = os.path.realpath(os.path.join(UPLOAD_DIR, row['pdf_path']))
    if not full.startswith(os.path.realpath(UPLOAD_DIR) + os.sep) or not os.path.isfile(full):
        abort(404)
    return send_file(full, as_attachment=True, download_name=f"{row['number']}.pdf")


# --- Dashboard --------------------------------------------------------------

@admin_bp.route('/admin')
@admin_required
def dashboard():
    db = get_db()
    stats = {
        'clients': db.execute("SELECT COUNT(*) c FROM users WHERE role = 'client'").fetchone()['c'],
        'quotes': db.execute("SELECT COUNT(*) c FROM quotes").fetchone()['c'],
        'invoices_unpaid': db.execute("SELECT COUNT(*) c FROM invoices WHERE status = 'unpaid'").fetchone()['c'],
        'tickets_open': db.execute("SELECT COUNT(*) c FROM tickets WHERE status != 'closed'").fetchone()['c'],
    }
    open_tickets = db.execute("""
        SELECT t.*, u.email, u.company FROM tickets t
        JOIN users u ON u.id = t.client_id
        WHERE t.status != 'closed' ORDER BY t.updated_at DESC LIMIT 10
    """).fetchall()
    return render_template('portal/admin/dashboard.html', stats=stats, open_tickets=open_tickets)


# --- Clients ----------------------------------------------------------------

@admin_bp.route('/admin/clients')
@admin_required
def clients():
    rows = get_db().execute(
        "SELECT * FROM users WHERE role = 'client' ORDER BY created_at DESC").fetchall()
    return render_template('portal/admin/clients.html', clients=rows)


@admin_bp.route('/admin/clients/new', methods=['POST'])
@admin_required
def client_new():
    email = (request.form.get('email') or '').strip()
    full_name = (request.form.get('full_name') or '').strip()
    company = (request.form.get('company') or '').strip()
    password = request.form.get('password') or ''
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        flash("Adresse e-mail invalide.", 'error')
        return redirect(url_for('admin.clients'))
    if len(password) < 8:
        flash("Le mot de passe doit faire au moins 8 caractères.", 'error')
        return redirect(url_for('admin.clients'))
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (email, password_hash, role, full_name, company, created_at) "
            "VALUES (?,?,'client',?,?,?)",
            (email, generate_password_hash(password), full_name, company, now_iso()))
        db.commit()
        flash(f"Client {email} créé.", 'ok')
    except Exception:
        flash("Un compte existe déjà avec cet e-mail.", 'error')
    return redirect(url_for('admin.clients'))


@admin_bp.route('/admin/clients/<int:cid>/toggle', methods=['POST'])
@admin_required
def client_toggle(cid):
    db = get_db()
    row = db.execute("SELECT active FROM users WHERE id = ? AND role = 'client'", (cid,)).fetchone()
    if row is None:
        abort(404)
    db.execute("UPDATE users SET active = ? WHERE id = ?", (0 if row['active'] else 1, cid))
    db.commit()
    return redirect(url_for('admin.clients'))


@admin_bp.route('/admin/clients/<int:cid>/password', methods=['POST'])
@admin_required
def client_password(cid):
    password = request.form.get('password') or ''
    if len(password) < 8:
        flash("Le mot de passe doit faire au moins 8 caractères.", 'error')
        return redirect(url_for('admin.clients'))
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE id = ? AND role = 'client'", (cid,)).fetchone() is None:
        abort(404)
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(password), cid))
    db.commit()
    flash("Mot de passe mis à jour.", 'ok')
    return redirect(url_for('admin.clients'))


def _client_choices():
    return get_db().execute(
        "SELECT id, email, company FROM users WHERE role = 'client' AND active = 1 ORDER BY email"
    ).fetchall()


# --- Quotes (devis) ---------------------------------------------------------

@admin_bp.route('/admin/quotes')
@admin_required
def quotes():
    rows = get_db().execute("""
        SELECT q.*, u.email, u.company FROM quotes q
        JOIN users u ON u.id = q.client_id ORDER BY q.created_at DESC
    """).fetchall()
    return render_template('portal/admin/quotes.html', quotes=rows, clients=_client_choices())


@admin_bp.route('/admin/quotes/new', methods=['POST'])
@admin_required
def quote_new():
    client_id = request.form.get('client_id', type=int)
    number = (request.form.get('number') or '').strip()
    title = (request.form.get('title') or '').strip()
    if not client_id or not number or not title:
        flash("Client, numéro et objet sont requis.", 'error')
        return redirect(url_for('admin.quotes'))
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE id = ? AND role = 'client'", (client_id,)).fetchone() is None:
        abort(400)
    db.execute(
        "INSERT INTO quotes (client_id, number, title, amount_cents, currency, status, pdf_path, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (client_id, number, title, _parse_amount(request.form.get('amount')),
         'EUR', request.form.get('status', 'draft'), _save_pdf(request.files.get('pdf')), now_iso()))
    db.commit()
    flash(f"Devis {number} créé.", 'ok')
    return redirect(url_for('admin.quotes'))


@admin_bp.route('/admin/quotes/<int:qid>/status', methods=['POST'])
@admin_required
def quote_status(qid):
    status = request.form.get('status', '')
    if status not in ('draft', 'sent', 'accepted', 'declined'):
        abort(400)
    db = get_db()
    db.execute("UPDATE quotes SET status = ? WHERE id = ?", (status, qid))
    db.commit()
    return redirect(url_for('admin.quotes'))


@admin_bp.route('/admin/quotes/<int:qid>/pdf')
@admin_required
def quote_pdf(qid):
    return _send_pdf(get_db().execute("SELECT * FROM quotes WHERE id = ?", (qid,)).fetchone())


# --- Invoices (facturation) -------------------------------------------------

@admin_bp.route('/admin/invoices')
@admin_required
def invoices():
    rows = get_db().execute("""
        SELECT i.*, u.email, u.company FROM invoices i
        JOIN users u ON u.id = i.client_id ORDER BY i.issued_at DESC
    """).fetchall()
    return render_template('portal/admin/invoices.html', invoices=rows, clients=_client_choices())


@admin_bp.route('/admin/invoices/new', methods=['POST'])
@admin_required
def invoice_new():
    client_id = request.form.get('client_id', type=int)
    number = (request.form.get('number') or '').strip()
    title = (request.form.get('title') or '').strip()
    if not client_id or not number or not title:
        flash("Client, numéro et objet sont requis.", 'error')
        return redirect(url_for('admin.invoices'))
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE id = ? AND role = 'client'", (client_id,)).fetchone() is None:
        abort(400)
    db.execute(
        "INSERT INTO invoices (client_id, number, title, amount_cents, currency, status, pdf_path, issued_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (client_id, number, title, _parse_amount(request.form.get('amount')),
         'EUR', request.form.get('status', 'unpaid'), _save_pdf(request.files.get('pdf')), now_iso()))
    db.commit()
    flash(f"Facture {number} créée.", 'ok')
    return redirect(url_for('admin.invoices'))


@admin_bp.route('/admin/invoices/<int:iid>/status', methods=['POST'])
@admin_required
def invoice_status(iid):
    status = request.form.get('status', '')
    if status not in ('unpaid', 'paid', 'cancelled'):
        abort(400)
    db = get_db()
    paid_at = now_iso() if status == 'paid' else None
    db.execute("UPDATE invoices SET status = ?, paid_at = ? WHERE id = ?", (status, paid_at, iid))
    db.commit()
    return redirect(url_for('admin.invoices'))


@admin_bp.route('/admin/invoices/<int:iid>/pdf')
@admin_required
def invoice_pdf(iid):
    return _send_pdf(get_db().execute("SELECT * FROM invoices WHERE id = ?", (iid,)).fetchone())


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
