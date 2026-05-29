#!/bin/bash
set -e

# Ensure database directory exists
mkdir -p /app/data

# Run database initialization and create default client if not exists
python -c "
import sqlite3
import os
import uuid
from datetime import datetime

DB_PATH = '/app/data/vertbacon.db'

# Ensure DB schema is created (same as in silverveil_backend.py)
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    name TEXT,
    created_at TEXT,
    modified_at TEXT,
    leverage REAL DEFAULT 100,
    tp REAL DEFAULT 2.0,
    sl REAL DEFAULT 1.0,
    asset_percent REAL DEFAULT 10.0,
    profit_percent REAL DEFAULT 0.0,
    is_active INTEGER DEFAULT 1
)''')
c.execute('''CREATE TABLE IF NOT EXISTS client_creds (
    client_id TEXT PRIMARY KEY,
    apex_key TEXT,
    apex_secret TEXT,
    apex_omni TEXT,
    apex_passphrase TEXT,
    apex_account_id TEXT,
    okx_key TEXT, okx_secret TEXT, okx_passphrase TEXT,
    binance_key TEXT, binance_secret TEXT,
    dexari_wallet TEXT, dexly_wallet TEXT,
    withdrawal_wallets TEXT,
    FOREIGN KEY(client_id) REFERENCES clients(id)
)''')
# Add other tables if needed (simplified for demo)
conn.commit()

# Check if any client exists
c.execute('SELECT COUNT(*) FROM clients')
count = c.fetchone()[0]
if count == 0:
    # Create a default client (you can override credentials via env)
    client_id = os.environ.get('DEFAULT_CLIENT_ID', 'default_client')
    name = os.environ.get('DEFAULT_CLIENT_NAME', 'Default Client')
    now = datetime.now().isoformat()
    c.execute('''INSERT INTO clients (id, name, created_at, modified_at, leverage, tp, sl, asset_percent, profit_percent)
                 VALUES (?,?,?,?,?,?,?,?,?)''',
              (client_id, name, now, now, 100, 2.0, 1.0, 10.0, 0.0))
    conn.commit()
    print(f'✅ Created default client: {client_id}')
else:
    print(f'✅ Database already has {count} client(s)')
conn.close()
"

# Start supervisor (runs both signer and backend)
exec supervisord -c /app/supervisord.conf