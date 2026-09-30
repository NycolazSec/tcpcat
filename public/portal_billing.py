"""Billing helpers shared by the admin/client routes and PDF generation:
line items and VAT totals, document numbering, dates, and OEM license tiers
and keys. Amounts are integer cents throughout; rounding is half-up.
"""

import os
import secrets
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

DEFAULT_VAT = float(os.environ.get('PORTAL_DEFAULT_VAT', '20'))
QUOTE_VALIDITY_DAYS = 30
INVOICE_DUE_DAYS = 30
DEFAULT_PAYMENT_TERMS = os.environ.get(
    'PORTAL_PAYMENT_TERMS',
    'Paiement par virement bancaire à 30 jours à réception de facture.')
MAX_ITEMS = 50
_MAX_CENTS = 10 ** 11  # 1 billion EUR: anything above is a typo

# One-click lines for the quote/invoice editor, taken from the OEM price list
# in COMMERCIAL-LICENSE.md. Unit prices excl. VAT, in cents.
ITEM_PRESETS = [
    ('Startup · 1 an',
     'Licence OEM tcpcat - Startup & Single-Product, 1 an (maintenance et mises à jour incluses)', 398000),
    ('Startup · 1 trimestre',
     'Licence OEM tcpcat - Startup & Single-Product, 1 trimestre', 118000),
    ('Mid-Market · perpétuelle',
     'Licence OEM tcpcat - Mid-Market, perpétuelle (1 produit / appliance)', 1998000),
    ('Maintenance Mid-Market · 1 an',
     'Maintenance et mises à jour tcpcat - Mid-Market, 1 an', 498000),
    ('Enterprise · perpétuelle',
     'Licence OEM tcpcat - Enterprise, perpétuelle', 3998000),
    ('Maintenance Enterprise · 1 an',
     'Maintenance et mises à jour tcpcat - Enterprise, 1 an', 998000),
]

# License tiers and the default validity they imply when a license is
# created: None = perpetual / no maintenance end.
LICENSE_TIERS = {
    'startup':    {'label': 'Startup & Single-Product', 'term_years': 1,    'maintenance_years': 1},
    'midmarket':  {'label': 'Mid-Market OEM',           'term_years': None, 'maintenance_years': 1},
    'enterprise': {'label': 'Enterprise OEM',           'term_years': None, 'maintenance_years': 1},
    'custom':     {'label': 'Sur mesure',               'term_years': None, 'maintenance_years': None},
}


def tier_label(tier):
    return LICENSE_TIERS.get(tier, {}).get('label', tier)


# --- Dates ------------------------------------------------------------------

def today_iso():
    return date.today().isoformat()


def add_days(iso, days):
    return (date.fromisoformat(iso[:10]) + timedelta(days=days)).isoformat()


def add_years(iso, years):
    d = date.fromisoformat(iso[:10])
    try:
        return d.replace(year=d.year + years).isoformat()
    except ValueError:  # 29 February -> 28 February
        return d.replace(year=d.year + years, day=28).isoformat()


def parse_date(raw):
    """'YYYY-MM-DD' -> same string, anything else (incl. blank) -> None."""
    raw = (raw or '').strip()
    try:
        return date.fromisoformat(raw).isoformat() if raw else None
    except ValueError:
        return None


def fmt_date(iso):
    """ISO date/datetime -> 'dd/mm/yyyy' (blank stays blank)."""
    if not iso:
        return ''
    y, m, d = iso[:10].split('-')
    return f"{d}/{m}/{y}"


# --- Amounts ----------------------------------------------------------------

def _to_int(value):
    return int(Decimal(value).quantize(Decimal('1'), rounding=ROUND_HALF_UP))


def parse_amount(raw):
    """User-entered euros ('3 980,00', '3980.5', '-150') -> cents.
    Blank -> 0; invalid -> None."""
    raw = (raw or '').strip().replace(' ', '').replace(' ', '').replace(',', '.')
    raw = raw.replace('€', '').replace('EUR', '')
    if not raw:
        return 0
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return None
    if not value.is_finite():
        return None
    cents = _to_int(value * 100)
    return cents if abs(cents) < _MAX_CENTS else None


def parse_quantity(raw):
    """Blank -> 1; must be > 0 and reasonable; invalid -> None."""
    raw = (raw or '').strip().replace(',', '.')
    if not raw:
        return 1.0
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return None
    if not value.is_finite() or value <= 0 or value > 1_000_000:
        return None
    return float(round(value, 3))


def parse_vat(raw):
    """VAT rate in percent, 0-100. Blank -> 0; invalid -> None."""
    raw = (raw or '').strip().replace(',', '.').rstrip('%').strip()
    if not raw:
        return 0.0
    try:
        value = Decimal(raw)
    except InvalidOperation:
        return None
    if not value.is_finite() or value < 0 or value > 100:
        return None
    return float(round(value, 2))


def line_total(item):
    return _to_int(Decimal(str(item['quantity'])) * item['unit_price_cents'])


def totals(items, vat_rate):
    ht = sum(line_total(i) for i in items)
    vat = _to_int(Decimal(ht) * Decimal(str(vat_rate or 0)) / 100)
    return {'ht': ht, 'vat': vat, 'ttc': ht + vat}


# --- Line items -------------------------------------------------------------

_ITEM_FK = {'quote': 'quote_id', 'invoice': 'invoice_id'}


def parse_items(form):
    """Line items from the editor's parallel lists item_desc / item_qty /
    item_price. Fully empty rows are ignored. Returns (items, errors)."""
    descs = form.getlist('item_desc')
    qtys = form.getlist('item_qty')
    prices = form.getlist('item_price')
    items, errors = [], []
    for i, desc in enumerate(descs[:MAX_ITEMS]):
        desc = (desc or '').strip()
        qty_raw = qtys[i] if i < len(qtys) else ''
        price_raw = prices[i] if i < len(prices) else ''
        if not desc:
            if price_raw.strip():
                errors.append(f"Ligne {i + 1} : désignation manquante.")
            continue
        qty = parse_quantity(qty_raw)
        price = parse_amount(price_raw)
        if qty is None:
            errors.append(f"Ligne {i + 1} : quantité invalide.")
            continue
        if price is None:
            errors.append(f"Ligne {i + 1} : prix unitaire invalide.")
            continue
        items.append({'description': desc[:500], 'quantity': qty, 'unit_price_cents': price})
    return items, errors


def load_items(db, kind, doc_id):
    col = _ITEM_FK[kind]
    rows = db.execute(
        f'SELECT description, quantity, unit_price_cents FROM doc_items '
        f'WHERE {col} = ? ORDER BY position, id', (doc_id,)).fetchall()
    return [dict(r) for r in rows]


def save_items(db, kind, doc_id, items):
    col = _ITEM_FK[kind]
    db.execute(f'DELETE FROM doc_items WHERE {col} = ?', (doc_id,))
    for pos, it in enumerate(items):
        db.execute(
            f'INSERT INTO doc_items ({col}, position, description, quantity, unit_price_cents) '
            'VALUES (?,?,?,?,?)',
            (doc_id, pos, it['description'], it['quantity'], it['unit_price_cents']))


def items_for_display(row, items):
    """Documents created before line items existed have none: present their
    title and amount as a single line so pages and PDFs still add up."""
    if items:
        return items
    return [{'description': row['title'], 'quantity': 1, 'unit_price_cents': row['amount_cents'] or 0}]


def next_number(db, table, prefix):
    """Next sequential number for this year, e.g. DEV-2026-004."""
    stem = f"{prefix}-{date.today().year}-"
    n = 0
    for row in db.execute(f"SELECT number FROM {table} WHERE number LIKE ?", (stem + '%',)):
        tail = row['number'][len(stem):]
        if tail.isdigit():
            n = max(n, int(tail))
    return f"{stem}{n + 1:03d}"


# --- Licenses ---------------------------------------------------------------

_KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # no 0/O, 1/I


def generate_license_key(db):
    while True:
        groups = (''.join(secrets.choice(_KEY_ALPHABET) for _ in range(4)) for _ in range(4))
        key = 'TCPC-' + '-'.join(groups)
        if db.execute('SELECT 1 FROM licenses WHERE license_key = ?', (key,)).fetchone() is None:
            return key


def license_state(row, today=None):
    """'active' | 'expired' | 'suspended' | 'revoked'."""
    if row['status'] != 'active':
        return row['status']
    if row['end_date'] and row['end_date'] < (today or today_iso()):
        return 'expired'
    return 'active'


def maintenance_state(row, today=None):
    """None (no maintenance) | 'expired' | 'soon' (<= 30 days) | 'ok'."""
    until = row['maintenance_until']
    if not until:
        return None
    today = today or today_iso()
    if until < today:
        return 'expired'
    if until <= add_days(today, 30):
        return 'soon'
    return 'ok'
