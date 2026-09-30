"""On-the-fly PDF generation for quotes (devis) and invoices (factures).

Uses fpdf2 with the built-in Helvetica core font (Latin-1), so amounts are
written with the "EUR" currency code rather than the euro glyph, which that
font cannot encode. No binary font is bundled.

Issuer identity and the legally-required mentions are read from the
environment (see ISSUER_* below). Fill them in so the generated documents are
compliant; empty lines are simply omitted.
"""

import io
import os

from fpdf import FPDF

# --- Issuer identity (configure via environment) ----------------------------
ISSUER_BRAND = os.environ.get('ISSUER_BRAND', 'tcpcat')
ISSUER_NAME = os.environ.get('ISSUER_NAME', 'Nicolas Blondelle')
ISSUER_ADDRESS = os.environ.get('ISSUER_ADDRESS', '')      # e.g. "12 rue X\n59000 Lille, France"
ISSUER_EMAIL = os.environ.get('ISSUER_EMAIL', 'support@tcpcat.io')
ISSUER_SIRET = os.environ.get('ISSUER_SIRET', '')          # SIRET / registration no.
ISSUER_VAT = os.environ.get('ISSUER_VAT', '')              # VAT no., or leave empty
# Free-text legal footer, e.g. "TVA non applicable, art. 293 B du CGI." or
# payment terms. Shown as-is at the bottom of every document.
ISSUER_LEGAL = os.environ.get('ISSUER_LEGAL', '')

# Palette (matches the site's paper/ink theme).
INK = (27, 31, 26)
MUTED = (92, 99, 90)
RULE = (194, 200, 188)
STAMP = (181, 69, 31)


def _money(cents, currency='EUR'):
    body = f"{(cents or 0) / 100:,.2f}".replace(',', ' ').replace('.', ',')
    return f"{body} {currency or 'EUR'}"


def _clean(text):
    """Replace glyphs the core font can't encode with ASCII equivalents."""
    if text is None:
        return ''
    return (str(text)
            .replace('—', '-').replace('–', '-')   # em/en dash
            .replace('’', "'").replace('‘', "'")   # curly quotes
            .replace('“', '"').replace('”', '"')
            .replace('€', 'EUR')                         # euro sign
            .replace('…', '...'))


class _Doc(FPDF):
    def __init__(self, kind_label):
        super().__init__(format='A4')
        self.kind_label = kind_label
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(20, 18, 20)

    def header(self):
        self.set_xy(20, 16)
        self.set_font('Helvetica', 'B', 22)
        self.set_text_color(*INK)
        self.cell(0, 10, _clean(ISSUER_BRAND))
        # accent dot
        w = self.get_string_width(_clean(ISSUER_BRAND))
        self.set_text_color(*STAMP)
        self.set_font('Helvetica', 'B', 22)
        self.cell(6, 10, '.')
        # document type, right-aligned
        self.set_xy(-70, 16)
        self.set_text_color(*MUTED)
        self.set_font('Helvetica', 'B', 16)
        self.cell(50, 10, self.kind_label, align='R')
        self.ln(16)


def _issuer_block(pdf):
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(*MUTED)
    lines = [ISSUER_NAME]
    if ISSUER_ADDRESS:
        lines += ISSUER_ADDRESS.splitlines()
    if ISSUER_EMAIL:
        lines.append(ISSUER_EMAIL)
    for ln in lines:
        pdf.cell(0, 5, _clean(ln), new_x='LMARGIN', new_y='NEXT')


def _meta_and_client(pdf, doc, client, date_label):
    top = pdf.get_y()
    # Left: client block
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 5, ('DEVIS POUR' if doc['_kind'] == 'quote' else 'FACTURE POUR'),
             new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(*INK)
    client_lines = [client['company'] or client['full_name'] or client['email']]
    if client['company'] and client['full_name']:
        client_lines.append(client['full_name'])
    client_lines.append(client['email'])
    for ln in client_lines:
        pdf.cell(0, 5, _clean(ln), new_x='LMARGIN', new_y='NEXT')

    # Right: document meta box
    pdf.set_xy(-90, top)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(*MUTED)
    rows = [
        ('Numéro', doc['number']),
        (date_label, (doc['_date'] or '')[:10]),
        ('Statut', doc['_status_fr']),
    ]
    for label, value in rows:
        pdf.set_x(-90)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(*MUTED)
        pdf.cell(30, 6, _clean(label))
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(*INK)
        pdf.cell(40, 6, _clean(value), align='R', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(6)


def _line_items(pdf, doc):
    pdf.ln(4)
    y = pdf.get_y()
    pdf.set_draw_color(*RULE)
    pdf.line(20, y, 190, y)
    pdf.ln(2)
    # header row
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_text_color(*MUTED)
    pdf.cell(120, 7, 'DESCRIPTION')
    pdf.cell(50, 7, 'MONTANT', align='R', new_x='LMARGIN', new_y='NEXT')
    pdf.set_draw_color(*RULE)
    y = pdf.get_y()
    pdf.line(20, y, 190, y)
    pdf.ln(3)
    # the single line item
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(*INK)
    x = pdf.get_x()
    y = pdf.get_y()
    pdf.multi_cell(120, 6, _clean(doc['title']))
    pdf.set_xy(x + 120, y)
    pdf.cell(50, 6, _money(doc['amount_cents'], doc['currency']), align='R',
             new_x='LMARGIN', new_y='NEXT')
    pdf.ln(4)
    y = pdf.get_y()
    pdf.line(20, y, 190, y)
    pdf.ln(3)
    # total
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(*INK)
    pdf.cell(120, 8, 'TOTAL')
    pdf.cell(50, 8, _money(doc['amount_cents'], doc['currency']), align='R',
             new_x='LMARGIN', new_y='NEXT')


def _footer_block(pdf):
    pdf.ln(14)
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(*MUTED)
    legal = []
    if ISSUER_SIRET:
        legal.append(f"SIRET : {ISSUER_SIRET}")
    if ISSUER_VAT:
        legal.append(f"TVA : {ISSUER_VAT}")
    if legal:
        pdf.cell(0, 5, _clean('  -  '.join(legal)), new_x='LMARGIN', new_y='NEXT')
    if ISSUER_LEGAL:
        for ln in ISSUER_LEGAL.splitlines():
            pdf.cell(0, 5, _clean(ln), new_x='LMARGIN', new_y='NEXT')


def _build(kind, doc_row, client_row):
    """kind: 'quote' or 'invoice'. Returns PDF bytes."""
    is_quote = kind == 'quote'
    doc = dict(doc_row)
    doc['_kind'] = kind
    doc['_date'] = doc_row['created_at'] if is_quote else doc_row['issued_at']
    status_map = {
        'draft': 'Brouillon', 'sent': 'Envoyé', 'accepted': 'Accepté', 'declined': 'Refusé',
        'unpaid': 'Impayée', 'paid': 'Payée', 'cancelled': 'Annulée',
    }
    doc['_status_fr'] = status_map.get(doc_row['status'], doc_row['status'])

    pdf = _Doc('DEVIS' if is_quote else 'FACTURE')
    pdf.add_page()
    _issuer_block(pdf)
    pdf.ln(6)
    _meta_and_client(pdf, doc, client_row, 'Date' if is_quote else "Émise le")
    _line_items(pdf, doc)
    _footer_block(pdf)
    out = pdf.output()
    return bytes(out)


def build_quote_pdf(doc_row, client_row):
    return _build('quote', doc_row, client_row)


def build_invoice_pdf(doc_row, client_row):
    return _build('invoice', doc_row, client_row)


def as_response(pdf_bytes, download_name):
    """Wrap PDF bytes in a Flask send_file response."""
    from flask import send_file
    return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf',
                     as_attachment=True, download_name=download_name)
