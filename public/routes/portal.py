"""Client space (/pro): a logged-in client sees only their own quotes,
invoices, and support tickets. Every query is scoped to the session user's
id, and PDF downloads verify ownership before serving the file.
"""

import os

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort, send_file)

from portal_db import get_db, now_iso, UPLOAD_DIR
from portal_auth import client_required, current_user
import portal_pdf

portal_bp = Blueprint('portal', __name__, template_folder='../templates')


@portal_bp.route('/pro')
@client_required
def dashboard():
    db = get_db()
    uid = current_user()['id']
    quotes = db.execute('SELECT * FROM quotes WHERE client_id = ? ORDER BY created_at DESC', (uid,)).fetchall()
    invoices = db.execute('SELECT * FROM invoices WHERE client_id = ? ORDER BY issued_at DESC', (uid,)).fetchall()
    tickets = db.execute('SELECT * FROM tickets WHERE client_id = ? ORDER BY updated_at DESC', (uid,)).fetchall()
    return render_template('portal/dashboard.html', quotes=quotes, invoices=invoices, tickets=tickets)


def _owned_or_404(table, doc_id):
    row = get_db().execute(
        f'SELECT * FROM {table} WHERE id = ? AND client_id = ?',
        (doc_id, current_user()['id'])).fetchone()
    if row is None:
        abort(404)
    return row


def _send_pdf(row):
    if not row['pdf_path']:
        abort(404)
    # pdf_path stores only a basename inside UPLOAD_DIR; join and confirm the
    # resolved path stays within UPLOAD_DIR (defense against traversal).
    full = os.path.realpath(os.path.join(UPLOAD_DIR, row['pdf_path']))
    if not full.startswith(os.path.realpath(UPLOAD_DIR) + os.sep) or not os.path.isfile(full):
        abort(404)
    return send_file(full, as_attachment=True, download_name=f"{row['number']}.pdf")


@portal_bp.route('/pro/quote/<int:qid>/pdf')
@client_required
def quote_pdf(qid):
    row = _owned_or_404('quotes', qid)
    if row['pdf_path']:
        return _send_pdf(row)
    return portal_pdf.as_response(portal_pdf.build_quote_pdf(row, current_user()), f"{row['number']}.pdf")


@portal_bp.route('/pro/invoice/<int:iid>/pdf')
@client_required
def invoice_pdf(iid):
    row = _owned_or_404('invoices', iid)
    if row['pdf_path']:
        return _send_pdf(row)
    return portal_pdf.as_response(portal_pdf.build_invoice_pdf(row, current_user()), f"{row['number']}.pdf")


@portal_bp.route('/pro/tickets/new', methods=['POST'])
@client_required
def ticket_new():
    subject = (request.form.get('subject') or '').strip()
    body = (request.form.get('body') or '').strip()
    if not subject or not body:
        flash("Sujet et message sont requis.", 'error')
        return redirect(url_for('portal.dashboard'))
    db = get_db()
    ts = now_iso()
    cur = db.execute(
        'INSERT INTO tickets (client_id, subject, status, created_at, updated_at) VALUES (?,?,?,?,?)',
        (current_user()['id'], subject, 'open', ts, ts))
    db.execute(
        'INSERT INTO ticket_messages (ticket_id, author_role, body, created_at) VALUES (?,?,?,?)',
        (cur.lastrowid, 'client', body, ts))
    db.commit()
    return redirect(url_for('portal.ticket_view', tid=cur.lastrowid))


@portal_bp.route('/pro/tickets/<int:tid>', methods=['GET', 'POST'])
@client_required
def ticket_view(tid):
    db = get_db()
    ticket = _owned_or_404('tickets', tid)
    if request.method == 'POST':
        body = (request.form.get('body') or '').strip()
        if body:
            ts = now_iso()
            db.execute(
                'INSERT INTO ticket_messages (ticket_id, author_role, body, created_at) VALUES (?,?,?,?)',
                (tid, 'client', body, ts))
            db.execute("UPDATE tickets SET status = 'open', updated_at = ? WHERE id = ?", (ts, tid))
            db.commit()
        return redirect(url_for('portal.ticket_view', tid=tid))
    messages = db.execute(
        'SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at', (tid,)).fetchall()
    return render_template('portal/ticket.html', ticket=ticket, messages=messages)
