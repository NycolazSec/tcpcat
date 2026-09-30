"""PDF generation for quotes (devis), invoices (factures) and license
certificates.

Uses fpdf2 with the built-in Helvetica core font (Latin-1), so amounts are
written with the "EUR" code rather than the euro glyph, which that font cannot
encode. Any other character outside Latin-1 is replaced, so user-entered text
can never break generation. No binary font is bundled.

Issuer identity and the legally-required mentions are read from the
environment (see ISSUER_* below). Fill them in so the generated documents are
compliant; empty values are simply omitted.
"""

import io
import os

from fpdf import FPDF

import portal_billing as billing

# --- Issuer identity (configure via environment) ----------------------------
ISSUER_BRAND = os.environ.get('ISSUER_BRAND', 'tcpcat')
ISSUER_NAME = os.environ.get('ISSUER_NAME', 'Nicolas Blondelle')
ISSUER_ADDRESS = os.environ.get('ISSUER_ADDRESS', '')      # e.g. "12 rue X\n59000 Lille, France"
ISSUER_EMAIL = os.environ.get('ISSUER_EMAIL', 'support@tcpcat.io')
ISSUER_SIRET = os.environ.get('ISSUER_SIRET', '')          # SIRET / registration no.
ISSUER_VAT = os.environ.get('ISSUER_VAT', '')              # VAT no., or leave empty
ISSUER_IBAN = os.environ.get('ISSUER_IBAN', '')            # printed on invoices for transfers
# Free-text legal line, e.g. "TVA non applicable, art. 293 B du CGI."
ISSUER_LEGAL = os.environ.get('ISSUER_LEGAL', '')
# Mentions required on French B2B invoices (late-payment penalties, fixed
# recovery indemnity, discount terms). Override if your terms differ.
ISSUER_INVOICE_TERMS = os.environ.get(
    'ISSUER_INVOICE_TERMS',
    "En cas de retard de paiement : pénalités au taux de 3 fois le taux d'intérêt légal "
    "et indemnité forfaitaire de 40 EUR pour frais de recouvrement (art. L441-10 du "
    "Code de commerce). Pas d'escompte pour paiement anticipé.")

# Palette (matches the site's paper/ink theme).
INK = (27, 31, 26)
MUTED = (92, 99, 90)
RULE = (194, 200, 188)
SHADE = (238, 241, 236)
STAMP = (181, 69, 31)

# Items table: (header, width mm, align). Widths sum to the 170 mm body.
_COLS = [('DÉSIGNATION', 92, 'L'), ('QTÉ', 16, 'R'), ('PU HT', 30, 'R'), ('TOTAL HT', 32, 'R')]

_STATE_FR = {
    'active': 'Active', 'expired': 'Expirée', 'suspended': 'Suspendue', 'revoked': 'Révoquée',
}


def _clean(text):
    """Map common typographic characters to Latin-1 equivalents, then replace
    anything the core font still can't encode."""
    if text is None:
        return ''
    text = (str(text)
            .replace('—', '-').replace('–', '-')    # em/en dash
            .replace('’', "'").replace('‘', "'")    # curly quotes
            .replace('“', '"').replace('”', '"')
            .replace('€', 'EUR')                          # euro sign
            .replace('…', '...')
            .replace(' ', ' '))                           # narrow nbsp
    return text.encode('latin-1', 'replace').decode('latin-1')


def _money(cents, currency='EUR'):
    body = f"{(cents or 0) / 100:,.2f}".replace(',', ' ').replace('.', ',')
    return f"{body} {currency or 'EUR'}"


def _num(value):
    """1.0 -> '1', 2.5 -> '2,5', 5.5 -> '5,5'."""
    return ('%.3f' % value).rstrip('0').rstrip('.').replace('.', ',')


class _Doc(FPDF):
    def __init__(self, label):
        super().__init__(format='A4')
        self.label = label
        self.set_margins(20, 18, 20)
        self.set_auto_page_break(auto=True, margin=24)

    def header(self):
        brand = _clean(ISSUER_BRAND)
        self.set_y(16)
        self.set_font('Helvetica', 'B', 22)
        self.set_text_color(*INK)
        self.cell(self.get_string_width(brand) + 0.5, 10, brand)
        self.set_text_color(*STAMP)
        self.cell(6, 10, '.')
        self.set_xy(self.l_margin, 16)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(*MUTED)
        self.cell(self.epw, 10, _clean(self.label), align='R')
        self.set_y(34)

    def footer(self):
        self.set_y(-17)
        self.set_draw_color(*RULE)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(1.5)
        self.set_font('Helvetica', '', 7)
        self.set_text_color(*MUTED)
        parts = [ISSUER_NAME]
        if ISSUER_SIRET:
            parts.append(f"SIRET {ISSUER_SIRET}")
        if ISSUER_VAT:
            parts.append(f"TVA {ISSUER_VAT}")
        if ISSUER_EMAIL:
            parts.append(ISSUER_EMAIL)
        self.cell(self.epw - 20, 4, _clean('  ·  '.join(p for p in parts if p)))
        self.cell(20, 4, f"{self.page_no()}/{{nb}}", align='R')

    def ensure_space(self, height):
        if self.get_y() + height > self.page_break_trigger:
            self.add_page()


# --- Building blocks --------------------------------------------------------

def _issuer_and_meta(pdf, meta_rows):
    """Issuer block on the left, document meta (label/value) on the right."""
    top = pdf.get_y()
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(*INK)
    pdf.cell(90, 5, _clean(ISSUER_NAME), new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(*MUTED)
    lines = ISSUER_ADDRESS.splitlines() if ISSUER_ADDRESS else []
    if ISSUER_EMAIL:
        lines.append(ISSUER_EMAIL)
    if ISSUER_SIRET:
        lines.append(f"SIRET : {ISSUER_SIRET}")
    if ISSUER_VAT:
        lines.append(f"TVA intracom. : {ISSUER_VAT}")
    for ln in lines:
        pdf.cell(90, 4.3, _clean(ln), new_x='LMARGIN', new_y='NEXT')
    left_bottom = pdf.get_y()

    x = pdf.l_margin + pdf.epw - 85
    pdf.set_y(top)
    for label, value in meta_rows:
        pdf.set_x(x)
        pdf.set_font('Helvetica', '', 8.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(38, 5.5, _clean(label))
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(*INK)
        pdf.cell(47, 5.5, _clean(value), align='R', new_x='LMARGIN', new_y='NEXT')
    pdf.set_y(max(left_bottom, pdf.get_y()) + 7)


def _client_box(pdf, client, heading):
    """Recipient block in a framed box on the right half (French layout)."""
    x = pdf.l_margin + pdf.epw / 2 + 5
    w = pdf.epw / 2 - 5
    y0 = pdf.get_y()
    lines = []
    name = client['company'] or client['full_name'] or client['email']
    lines.append(('B', 10, INK, name))
    if client['company'] and client['full_name']:
        lines.append(('', 9, INK, client['full_name']))
    address = client['address'] if 'address' in client.keys() else None
    for ln in (address or '').splitlines():
        if ln.strip():
            lines.append(('', 9, INK, ln.strip()))
    lines.append(('', 8.5, MUTED, client['email']))
    vat_number = client['vat_number'] if 'vat_number' in client.keys() else None
    if vat_number:
        lines.append(('', 8.5, MUTED, f"TVA intracom. : {vat_number}"))

    pdf.set_xy(x + 4, y0 + 3)
    pdf.set_font('Helvetica', 'B', 7)
    pdf.set_text_color(*MUTED)
    pdf.cell(w - 8, 4, heading, new_x='LEFT', new_y='NEXT')
    for style, size, color, text in lines:
        pdf.set_x(x + 4)
        pdf.set_font('Helvetica', style, size)
        pdf.set_text_color(*color)
        pdf.cell(w - 8, 4.8, _clean(text), new_x='LEFT', new_y='NEXT')
    y1 = pdf.get_y() + 3
    pdf.set_draw_color(*RULE)
    pdf.rect(x, y0, w, y1 - y0)
    pdf.set_y(y1 + 7)


def _subject(pdf, title):
    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(*MUTED)
    pdf.cell(16, 6, 'Objet :')
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(*INK)
    pdf.multi_cell(pdf.epw - 16, 6, _clean(title), new_x='LMARGIN', new_y='NEXT')
    pdf.ln(3)


def _items_table(pdf, items):
    def head():
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_text_color(*MUTED)
        pdf.set_fill_color(*SHADE)
        for label, width, align in _COLS:
            pdf.cell(width, 7, label, align=align, fill=True)
        pdf.ln(7)
        pdf.set_font('Helvetica', '', 9.5)
        pdf.set_text_color(*INK)

    head()
    desc_w = _COLS[0][1] - 3
    for it in items:
        desc = _clean(it['description'])
        n_lines = len(pdf.multi_cell(desc_w, 5, desc, dry_run=True, output='LINES')) or 1
        row_h = n_lines * 5 + 3
        if pdf.get_y() + row_h > pdf.page_break_trigger:
            pdf.add_page()
            head()
        x, y = pdf.l_margin, pdf.get_y()
        pdf.set_xy(x + 1.5, y + 1.5)
        pdf.multi_cell(desc_w, 5, desc)
        pdf.set_xy(x + _COLS[0][1], y + 1.5)
        pdf.cell(_COLS[1][1], 5, _num(it['quantity']), align='R')
        pdf.cell(_COLS[2][1], 5, _money(it['unit_price_cents']), align='R')
        pdf.cell(_COLS[3][1], 5, _money(billing.line_total(it)), align='R')
        pdf.set_y(y + row_h)
        pdf.set_draw_color(*RULE)
        pdf.line(x, pdf.get_y(), x + pdf.epw, pdf.get_y())


def _totals(pdf, t, vat_rate):
    rows = [('Total HT', t['ht'])]
    if vat_rate:
        rows.append((f"TVA {_num(vat_rate)} %", t['vat']))
        final = ('Total TTC', t['ttc'])
    else:
        final = ('Net à payer', t['ttc'])
    pdf.ensure_space(7 * len(rows) + 14)
    pdf.ln(3)
    x = pdf.l_margin + pdf.epw - 85
    for label, value in rows:
        pdf.set_x(x)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(*MUTED)
        pdf.cell(45, 6.5, _clean(label))
        pdf.set_font('Helvetica', '', 9.5)
        pdf.set_text_color(*INK)
        pdf.cell(40, 6.5, _money(value), align='R', new_x='LMARGIN', new_y='NEXT')
    pdf.set_x(x)
    pdf.set_fill_color(*SHADE)
    pdf.set_font('Helvetica', 'B', 10.5)
    pdf.cell(45, 9, ' ' + _clean(final[0]), fill=True)
    pdf.cell(40, 9, _money(final[1]) + ' ', align='R', fill=True, new_x='LMARGIN', new_y='NEXT')
    pdf.ln(6)


def _text_blocks(pdf, blocks):
    """Titled paragraphs (conditions, notes, legal mentions); empty ones skipped."""
    for title, text in blocks:
        if not text or not str(text).strip():
            continue
        pdf.ensure_space(14)
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(0, 5, _clean(title.upper()), new_x='LMARGIN', new_y='NEXT')
        pdf.set_font('Helvetica', '', 8.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(pdf.epw, 4.4, _clean(text), new_x='LMARGIN', new_y='NEXT')
        pdf.ln(2.5)


def _acceptance_box(pdf, doc):
    """'Bon pour accord' signature area, or the record of online acceptance."""
    pdf.ensure_space(38)
    pdf.ln(2)
    w, h = 85, 30
    x = pdf.l_margin + pdf.epw - w
    y = pdf.get_y()
    pdf.set_draw_color(*RULE)
    pdf.rect(x, y, w, h)
    pdf.set_xy(x + 4, y + 3)
    pdf.set_font('Helvetica', 'B', 7.5)
    pdf.set_text_color(*MUTED)
    pdf.cell(w - 8, 4, 'BON POUR ACCORD', new_x='LEFT', new_y='NEXT')
    pdf.set_font('Helvetica', '', 8)
    if doc['status'] == 'accepted' and doc['accepted_at']:
        pdf.set_text_color(*INK)
        pdf.multi_cell(w - 8, 4.2, _clean(
            f"Devis accepté en ligne par le client le {billing.fmt_date(doc['accepted_at'])} "
            f"à {doc['accepted_at'][11:16]} (UTC), depuis son espace client tcpcat."))
    else:
        pdf.multi_cell(w - 8, 4.2, _clean(
            "Date, signature et cachet du client, précédés de la mention "
            "« Bon pour accord » :"))
    pdf.set_y(y + h + 4)


# --- Documents --------------------------------------------------------------

def build_quote_pdf(doc, client, items):
    items = billing.items_for_display(doc, items)
    t = billing.totals(items, doc['vat_rate'])
    pdf = _Doc('DEVIS')
    pdf.add_page()
    meta = [('Devis n°', doc['number']), ('Date', billing.fmt_date(doc['created_at']))]
    if doc['valid_until']:
        meta.append(('Valable jusqu\'au', billing.fmt_date(doc['valid_until'])))
    _issuer_and_meta(pdf, meta)
    _client_box(pdf, client, 'DESTINATAIRE')
    _subject(pdf, doc['title'])
    _items_table(pdf, items)
    _totals(pdf, t, doc['vat_rate'])
    blocks = []
    if doc['valid_until']:
        blocks.append(('Validité', f"Ce devis est valable jusqu'au {billing.fmt_date(doc['valid_until'])}."))
    blocks += [
        ('Conditions de paiement', doc['payment_terms']),
        ('Remarques', doc['notes']),
        ('Mentions', ISSUER_LEGAL),
    ]
    _text_blocks(pdf, blocks)
    _acceptance_box(pdf, doc)
    return bytes(pdf.output())


def build_invoice_pdf(doc, client, items, quote_number=None):
    items = billing.items_for_display(doc, items)
    t = billing.totals(items, doc['vat_rate'])
    pdf = _Doc('FACTURE ANNULÉE' if doc['status'] == 'cancelled' else 'FACTURE')
    pdf.add_page()
    meta = [('Facture n°', doc['number']), ('Date d\'émission', billing.fmt_date(doc['issued_at']))]
    if doc['due_date']:
        meta.append(('Échéance', billing.fmt_date(doc['due_date'])))
    if quote_number:
        meta.append(('Réf. devis', quote_number))
    if doc['status'] == 'paid' and doc['paid_at']:
        meta.append(('Payée le', billing.fmt_date(doc['paid_at'])))
    _issuer_and_meta(pdf, meta)
    _client_box(pdf, client, 'FACTURÉ À')
    _subject(pdf, doc['title'])
    _items_table(pdf, items)
    _totals(pdf, t, doc['vat_rate'])
    payment = doc['payment_terms'] or ''
    if ISSUER_IBAN:
        payment = (payment + '\n' if payment else '') + f"IBAN : {ISSUER_IBAN}"
    _text_blocks(pdf, [
        ('Conditions de paiement', payment),
        ('Remarques', doc['notes']),
        ('Mentions légales', '\n'.join(p for p in (ISSUER_INVOICE_TERMS, ISSUER_LEGAL) if p)),
    ])
    return bytes(pdf.output())


def build_license_pdf(lic, client):
    state = billing.license_state(lic)
    pdf = _Doc('CERTIFICAT DE LICENCE')
    pdf.add_page()
    _issuer_and_meta(pdf, [
        ('Émis le', billing.fmt_date(billing.today_iso())),
        ('Statut', _STATE_FR.get(state, state)),
    ])

    pdf.set_font('Helvetica', 'B', 15)
    pdf.set_text_color(*INK)
    pdf.cell(0, 9, 'Licence commerciale (OEM)', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 9.5)
    pdf.set_text_color(*MUTED)
    holder = client['company'] or client['full_name'] or client['email']
    pdf.multi_cell(pdf.epw, 5, _clean(
        f"{ISSUER_NAME} ({ISSUER_BRAND}) certifie que {holder} est titulaire d'une licence "
        f"commerciale {lic['product']} aux conditions ci-dessous. La licence est régie par "
        "le contrat de licence commerciale conclu entre les parties."),
        new_x='LMARGIN', new_y='NEXT')
    pdf.ln(6)

    # The key, prominently, in a shaded band.
    pdf.set_fill_color(*SHADE)
    pdf.set_font('Helvetica', 'B', 7.5)
    pdf.set_text_color(*MUTED)
    pdf.cell(0, 7, '  CLÉ DE LICENCE', fill=True, new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Courier', 'B', 15)
    pdf.set_text_color(*INK)
    pdf.cell(0, 11, '  ' + lic['license_key'], fill=True, new_x='LMARGIN', new_y='NEXT')
    pdf.ln(6)

    rows = [
        ('Titulaire', holder),
        ('Produit', lic['product']),
        ('Formule', billing.tier_label(lic['tier'])),
        ('Produits / appliances couverts', str(lic['seats'])),
        ('Début de validité', billing.fmt_date(lic['start_date'])),
        ('Fin de validité', billing.fmt_date(lic['end_date']) if lic['end_date'] else 'Perpétuelle'),
        ('Maintenance et mises à jour', ("jusqu'au " + billing.fmt_date(lic['maintenance_until']))
         if lic['maintenance_until'] else 'Non incluse'),
    ]
    for label, value in rows:
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(*MUTED)
        pdf.cell(70, 8, _clean(label))
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(*INK)
        pdf.cell(0, 8, _clean(value), new_x='LMARGIN', new_y='NEXT')
        pdf.set_draw_color(*RULE)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + pdf.epw, pdf.get_y())

    if state != 'active':
        pdf.ln(8)
        pdf.set_font('Helvetica', 'B', 13)
        pdf.set_text_color(*STAMP)
        pdf.cell(0, 8, _clean(f"LICENCE {_STATE_FR.get(state, state).upper()}"), align='C',
                 new_x='LMARGIN', new_y='NEXT')
    return bytes(pdf.output())


def as_response(pdf_bytes, download_name):
    """Wrap PDF bytes in a Flask send_file response."""
    from flask import send_file
    return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf',
                     as_attachment=True, download_name=download_name)
