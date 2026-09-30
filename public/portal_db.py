"""SQLite storage for the tcpcat client portal and admin back-office.

One small database holds users (admin + clients), quotes, invoices, and
support tickets. Connections are per-request (stored on flask.g) with
foreign keys enforced and rows returned as dict-like sqlite3.Row.

The DB file and uploaded PDFs live outside the repo (see PORTAL_DB_PATH /
PORTAL_UPLOAD_DIR) and must never be committed -- they hold customer data.
"""

import os
import sqlite3
from datetime import datetime, timezone

from flask import g

_BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('PORTAL_DB_PATH') or os.path.join(_BASE, 'data', 'portal.db')
UPLOAD_DIR = os.environ.get('PORTAL_UPLOAD_DIR') or os.path.join(_BASE, 'data', 'uploads')

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK(role IN ('admin','client')),
    full_name     TEXT,
    company       TEXT,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quotes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    number       TEXT NOT NULL,
    title        TEXT NOT NULL,
    amount_cents INTEGER NOT NULL DEFAULT 0,
    currency     TEXT NOT NULL DEFAULT 'EUR',
    status       TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','sent','accepted','declined')),
    pdf_path     TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    number       TEXT NOT NULL,
    title        TEXT NOT NULL,
    amount_cents INTEGER NOT NULL DEFAULT 0,
    currency     TEXT NOT NULL DEFAULT 'EUR',
    status       TEXT NOT NULL DEFAULT 'unpaid' CHECK(status IN ('unpaid','paid','cancelled')),
    pdf_path     TEXT,
    issued_at    TEXT NOT NULL,
    paid_at      TEXT
);

CREATE TABLE IF NOT EXISTS tickets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','pending','closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ticket_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id   INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_role TEXT NOT NULL CHECK(author_role IN ('admin','client')),
    body        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Line items of a quote or an invoice (exactly one of the two FKs is set).
CREATE TABLE IF NOT EXISTS doc_items (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    quote_id         INTEGER REFERENCES quotes(id) ON DELETE CASCADE,
    invoice_id       INTEGER REFERENCES invoices(id) ON DELETE CASCADE,
    position         INTEGER NOT NULL DEFAULT 0,
    description      TEXT NOT NULL,
    quantity         REAL NOT NULL DEFAULT 1,
    unit_price_cents INTEGER NOT NULL DEFAULT 0,
    CHECK ((quote_id IS NULL) != (invoice_id IS NULL))
);

-- Commercial (OEM) licenses held by client companies. end_date NULL means
-- perpetual; the effective "expired" state is derived from end_date.
CREATE TABLE IF NOT EXISTS licenses (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    license_key       TEXT NOT NULL UNIQUE,
    product           TEXT NOT NULL DEFAULT 'tcpcat',
    tier              TEXT NOT NULL CHECK(tier IN ('startup','midmarket','enterprise','custom')),
    seats             INTEGER NOT NULL DEFAULT 1,
    start_date        TEXT NOT NULL,
    end_date          TEXT,
    maintenance_until TEXT,
    status            TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','revoked')),
    notes             TEXT,
    invoice_id        INTEGER REFERENCES invoices(id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quotes_client   ON quotes(client_id);
CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices(client_id);
CREATE INDEX IF NOT EXISTS idx_tickets_client  ON tickets(client_id);
CREATE INDEX IF NOT EXISTS idx_msgs_ticket     ON ticket_messages(ticket_id);
CREATE INDEX IF NOT EXISTS idx_items_quote     ON doc_items(quote_id);
CREATE INDEX IF NOT EXISTS idx_items_invoice   ON doc_items(invoice_id);
CREATE INDEX IF NOT EXISTS idx_licenses_client ON licenses(client_id);
"""

# Columns added after the first release. Each is applied with ALTER TABLE only
# when missing, so an existing portal.db upgrades in place without data loss.
# vat_rate defaults to 0 so documents created before line items existed keep
# their original total.
MIGRATIONS = [
    ('users', 'address', 'TEXT'),
    ('users', 'vat_number', 'TEXT'),
    ('quotes', 'vat_rate', 'REAL NOT NULL DEFAULT 0'),
    ('quotes', 'valid_until', 'TEXT'),
    ('quotes', 'payment_terms', 'TEXT'),
    ('quotes', 'notes', 'TEXT'),
    ('quotes', 'accepted_at', 'TEXT'),
    ('invoices', 'vat_rate', 'REAL NOT NULL DEFAULT 0'),
    ('invoices', 'due_date', 'TEXT'),
    ('invoices', 'payment_terms', 'TEXT'),
    ('invoices', 'notes', 'TEXT'),
    ('invoices', 'quote_id', 'INTEGER REFERENCES quotes(id) ON DELETE SET NULL'),
]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def get_db():
    """Per-request connection, opened lazily and closed by close_db()."""
    if 'db' not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        g.db = conn
    return g.db


def close_db(_exc=None):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()


def _migrate(conn):
    for table, column, ddl in MIGRATIONS:
        existing = {row[1] for row in conn.execute(f'PRAGMA table_info({table})')}
        if column not in existing:
            conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')


def init_db():
    """Create the schema, apply column migrations, and create the upload
    directory. Idempotent."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


def init_app(app):
    app.teardown_appcontext(close_db)
