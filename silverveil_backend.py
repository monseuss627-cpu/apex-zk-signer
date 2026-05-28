#!/usr/bin/env python3
"""
SilverVeil Trading Terminal v36.0 - External ZK Signing Service
- All orders signed via https://apex-zk-signer-1.onrender.com
- Full UI + OKX order books / chart data
- EA uses real Perpetual balance
- ApexClient now calls external signer
"""

import sys
import asyncio
import json
import os
import sqlite3
import time
import uuid
import hmac
import hashlib
import base64
import re
import traceback
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Dict, List, Any, Set, Callable
from contextlib import asynccontextmanager

import httpx
import websockets
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# ------------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", 8000))
ZK_SIGNER_URL = "https://apex-zk-signer-1.onrender.com"   # external signing service

APEX_REST_BASE = "https://omni.apex.exchange"
OKX_REST_BASE = "https://www.okx.com"
OKX_WS_URL = "wss://ws.okx.com:8443/ws/v5/public"

SUPPORTED_SYMBOLS = ["BTC-USDT", "ETH-USDT", "SOL-USDT"]
SYMBOL_TO_OKX = {
    "BTC-USDT": "BTC-USDT-SWAP",
    "ETH-USDT": "ETH-USDT-SWAP",
    "SOL-USDT": "SOL-USDT-SWAP"
}

# ------------------------------------------------------------------------------
# PATHS & DATABASE
# ------------------------------------------------------------------------------
HOME = os.environ.get("HOME", "/data/data/com.termux/files/home")
BASE_DIR = os.path.join(HOME, "SilverVeil")
DB_DIR = os.path.join(BASE_DIR, "data")
EA_DIR = os.path.join(BASE_DIR, "ea_files")
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(EA_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(DB_DIR, "vertbacon.db")

active_signals: Dict[str, dict] = {}
active_ea_consumers: Dict[str, asyncio.Task] = {}
latest_prices: Dict[str, float] = {}
orderbook_cache: Dict[str, dict] = {}
websocket_connections: List[WebSocket] = []

# =============================================================================
# BROKER STATE MANAGER
# =============================================================================
class BrokerOrder(BaseModel):
    order_id: str
    broker_order_id: Optional[str] = None
    account_id: str
    symbol: str
    side: str
    quantity: float
    price: Optional[float] = None
    status: str = "PENDING"
    filled_quantity: float = 0.0
    created_at: datetime = datetime.now()

class Position(BaseModel):
    symbol: str
    side: str
    quantity: float
    entry_price: float
    unrealized_pnl: float
    realized_pnl: float = 0.0
    account_id: str

class AccountBalance(BaseModel):
    account_id: str
    total_equity: float
    available: float
    unrealized_pnl: float
    realized_pnl: float
    margin_used: float

class StateManager:
    def __init__(self):
        self.orders: Dict[str, BrokerOrder] = {}
        self.positions: Dict[str, Position] = {}
        self.balances: Dict[str, AccountBalance] = {}
        self._subscribers: Set[Callable] = set()
        self._lock = asyncio.Lock()

    async def update_order(self, order: BrokerOrder):
        async with self._lock:
            self.orders[order.order_id] = order
            await self._broadcast("order_update", order.dict())

    async def update_position(self, position: Position):
        async with self._lock:
            self.positions[position.symbol] = position
            await self._broadcast("position_update", position.dict())

    async def update_balance(self, balance: AccountBalance):
        async with self._lock:
            self.balances[balance.account_id] = balance
            await self._broadcast("balance_update", balance.dict())

    async def get_orders(self) -> List[BrokerOrder]:
        async with self._lock:
            return list(self.orders.values())

    async def get_positions(self) -> List[Position]:
        async with self._lock:
            return list(self.positions.values())

    async def get_balances(self) -> List[AccountBalance]:
        async with self._lock:
            return list(self.balances.values())

    def add_subscriber(self, callback: Callable):
        self._subscribers.add(callback)

    def remove_subscriber(self, callback: Callable):
        self._subscribers.discard(callback)

    async def _broadcast(self, event: str, data: dict):
        for cb in self._subscribers:
            try:
                await cb({"type": event, "data": data})
            except:
                pass

broker_state = StateManager()

# =============================================================================
# DATABASE SCHEMA
# =============================================================================
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
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
    for col, dtype in [('tp', 'REAL DEFAULT 2.0'), ('sl', 'REAL DEFAULT 1.0'),
                       ('asset_percent', 'REAL DEFAULT 10.0'), ('profit_percent', 'REAL DEFAULT 0.0')]:
        try:
            c.execute(f"ALTER TABLE clients ADD COLUMN {col} {dtype}")
        except sqlite3.OperationalError:
            pass

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
    try:
        c.execute("ALTER TABLE client_creds ADD COLUMN apex_account_id TEXT")
    except sqlite3.OperationalError:
        pass

    c.execute('''CREATE TABLE IF NOT EXISTS ea_files (
        id TEXT PRIMARY KEY,
        client_id TEXT,
        name TEXT,
        file_path TEXT,
        uploaded_at TEXT,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY(client_id) REFERENCES clients(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS pine_scripts (
        id TEXT PRIMARY KEY,
        client_id TEXT,
        name TEXT,
        code TEXT,
        created_at TEXT,
        updated_at TEXT,
        is_active INTEGER DEFAULT 0,
        FOREIGN KEY(client_id) REFERENCES clients(id)
    )''')
    for col in ['client_id', 'name', 'code', 'created_at', 'updated_at', 'is_active']:
        try:
            c.execute(f"ALTER TABLE pine_scripts ADD COLUMN {col} TEXT")
        except:
            pass
    c.execute('''CREATE TABLE IF NOT EXISTS active_signals (
        client_id TEXT PRIMARY KEY,
        action TEXT,
        strength REAL,
        price REAL,
        symbol TEXT,
        broker TEXT,
        expires_at TEXT,
        created_at TEXT,
        FOREIGN KEY(client_id) REFERENCES clients(id)
    )''')
    try:
        c.execute("ALTER TABLE active_signals ADD COLUMN broker TEXT DEFAULT 'apex'")
    except:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS trade_logs (
        id TEXT PRIMARY KEY,
        client_id TEXT,
        symbol TEXT,
        side TEXT,
        size REAL,
        price REAL,
        status TEXT,
        order_id TEXT,
        timestamp TEXT,
        pnl REAL DEFAULT 0,
        dry_run INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS signal_logs (
        id TEXT PRIMARY KEY,
        client_id TEXT,
        signal_type TEXT,
        strength REAL,
        timestamp TEXT,
        executed INTEGER DEFAULT 0,
        source TEXT DEFAULT 'pinescript'
    )''')
    try:
        c.execute("ALTER TABLE signal_logs ADD COLUMN source TEXT DEFAULT 'pinescript'")
    except:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS trading_pairs (
        id TEXT PRIMARY KEY,
        name TEXT,
        asset_a TEXT,
        asset_b TEXT,
        timeframe TEXT,
        lookback_period INTEGER,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS pair_positions (
        id TEXT PRIMARY KEY,
        pair_id TEXT,
        client_id TEXT,
        entry_price_a REAL,
        entry_price_b REAL,
        quantity_a REAL,
        quantity_b REAL,
        pnl REAL,
        opened_at TEXT,
        closed_at TEXT,
        is_open INTEGER DEFAULT 1,
        FOREIGN KEY(pair_id) REFERENCES trading_pairs(id),
        FOREIGN KEY(client_id) REFERENCES clients(id)
    )''')
    conn.commit()
    conn.close()
    print("✅ Database ready")

init_db()

# ------------------------------------------------------------------------------
# PYDANTIC MODELS
# ------------------------------------------------------------------------------
class ClientCreate(BaseModel):
    name: str
    client_id: str
    apex_key: str
    apex_secret: str
    apex_passphrase: str
    apex_omni: str
    apex_account_id: Optional[str] = None
    leverage: float = 100
    tp: float = 2.0
    sl: float = 1.0
    asset_percent: float = 10.0
    profit_percent: float = 0.0
    withdrawal_wallets: List[str] = []

class ClientUpdate(BaseModel):
    name: Optional[str] = None
    apex_key: Optional[str] = None
    apex_secret: Optional[str] = None
    apex_passphrase: Optional[str] = None
    apex_omni: Optional[str] = None
    apex_account_id: Optional[str] = None
    leverage: Optional[float] = None
    tp: Optional[float] = None
    sl: Optional[float] = None
    asset_percent: Optional[float] = None
    profit_percent: Optional[float] = None
    withdrawal_wallets: Optional[List[str]] = None

class PineScriptCreate(BaseModel):
    client_id: str
    name: str
    code: str
    symbol: str = "BTC-USDT"
    timeframe: str = "1h"

class SignalRequest(BaseModel):
    client_id: str
    action: str
    strength: float
    price: float
    symbol: str
    broker: str = "apex"

class TradeRequest(BaseModel):
    client_id: str
    symbol: str
    side: str
    size: float
    price: float
    tp: Optional[float] = None
    sl: Optional[float] = None
    dry_run: bool = False

class EASettings(BaseModel):
    client_id: str
    symbol: str
    broker: str = "apex"

class WithdrawRequest(BaseModel):
    client_id: str
    amount: str
    asset: str = "USDT"
    wallet_index: int = 0

# ------------------------------------------------------------------------------
# DATABASE HELPERS
# ------------------------------------------------------------------------------
def get_client(client_id: str) -> Optional[Dict]:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM clients WHERE id=?", (client_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as e:
        print(f"get_client error: {e}")
        return None

def get_client_creds(client_id: str) -> Optional[Dict]:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM client_creds WHERE client_id=?", (client_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        creds = dict(row)
        if creds.get("withdrawal_wallets"):
            try:
                creds["withdrawal_wallets"] = json.loads(creds["withdrawal_wallets"])
            except:
                creds["withdrawal_wallets"] = []
        else:
            creds["withdrawal_wallets"] = []
        return creds
    except Exception as e:
        print(f"get_client_creds error: {e}")
        return None

def save_client_creds(client_id: str, creds: Dict):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    wallets_json = json.dumps(creds.get("withdrawal_wallets", []))
    c.execute('''INSERT OR REPLACE INTO client_creds 
        (client_id, apex_key, apex_secret, apex_omni, apex_passphrase, apex_account_id,
         okx_key, okx_secret, okx_passphrase,
         binance_key, binance_secret,
         dexari_wallet, dexly_wallet, withdrawal_wallets)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (client_id, creds.get("apex_key"), creds.get("apex_secret"), creds.get("apex_omni"), creds.get("apex_passphrase"),
         creds.get("apex_account_id"),
         None, None, None, None, None, None, None, wallets_json))
    conn.commit()
    conn.close()

def update_client(client_id: str, data: Dict):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    fields = []
    values = []
    for field in ['name', 'leverage', 'tp', 'sl', 'asset_percent', 'profit_percent']:
        if field in data and data[field] is not None:
            fields.append(f"{field}=?")
            values.append(data[field])
    if fields:
        values.append(client_id)
        c.execute(f"UPDATE clients SET {','.join(fields)} WHERE id=?", values)
    cred_fields = []
    cred_values = []
    for field in ['apex_key', 'apex_secret', 'apex_omni', 'apex_passphrase', 'apex_account_id']:
        if field in data and data[field] is not None:
            cred_fields.append(f"{field}=?")
            cred_values.append(data[field])
    if 'withdrawal_wallets' in data and data['withdrawal_wallets'] is not None:
        cred_fields.append("withdrawal_wallets=?")
        cred_values.append(json.dumps(data['withdrawal_wallets']))
    if cred_fields:
        cred_values.append(client_id)
        c.execute(f"UPDATE client_creds SET {','.join(cred_fields)} WHERE client_id=?", cred_values)
    conn.commit()
    conn.close()

def log_trade(client_id: str, trade: Dict):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO trade_logs 
        (id, client_id, symbol, side, size, price, status, order_id, timestamp, pnl, dry_run)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (str(uuid.uuid4()), client_id, trade.get("symbol"), trade.get("side"),
         trade.get("size"), trade.get("price"), trade.get("status"),
         trade.get("order_id"), datetime.now().isoformat(), trade.get("pnl", 0), 0))
    conn.commit()
    conn.close()

def log_signal(client_id: str, signal_type: str, strength: float, executed: bool = False, source: str = "pinescript"):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO signal_logs (id, client_id, signal_type, strength, timestamp, executed, source)
                 VALUES (?,?,?,?,?,?,?)''',
              (str(uuid.uuid4()), client_id, signal_type, strength, datetime.now().isoformat(), 1 if executed else 0, source))
    conn.commit()
    conn.close()

def get_last_trade_pnl(client_id: str) -> float:
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT pnl FROM trade_logs WHERE client_id=? AND status='PLACED' ORDER BY timestamp DESC LIMIT 1", (client_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0.0

def save_pine_script_to_db(client_id: str, name: str, code: str):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    script_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    c.execute("UPDATE pine_scripts SET is_active=0 WHERE client_id=?", (client_id,))
    c.execute('''INSERT INTO pine_scripts (id, client_id, name, code, created_at, updated_at, is_active)
                 VALUES (?,?,?,?,?,?,1)''', (script_id, client_id, name, code, now, now))
    conn.commit()
    conn.close()
    return script_id

def get_active_pine_script(client_id: str) -> Optional[Dict]:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM pine_scripts WHERE client_id=? AND is_active=1 ORDER BY updated_at DESC LIMIT 1", (client_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None
    except:
        return None

def get_all_pine_scripts(client_id: str) -> List[Dict]:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, name, created_at FROM pine_scripts WHERE client_id=? ORDER BY updated_at DESC", (client_id,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
    except:
        return []

def get_pine_script_by_id(script_id: str) -> Optional[Dict]:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM pine_scripts WHERE id=?", (script_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None
    except:
        return None

def set_active_signal_db(client_id: str, action: str, strength: float, price: float, symbol: str, broker: str, duration_hours: int = 24):
    expires_at = (datetime.now() + timedelta(hours=duration_hours)).isoformat()
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO active_signals 
        (client_id, action, strength, price, symbol, broker, expires_at, created_at)
        VALUES (?,?,?,?,?,?,?,?)''',
        (client_id, action, strength, price, symbol, broker, expires_at, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_active_signal_db(client_id: str) -> Optional[Dict]:
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM active_signals WHERE client_id=? AND expires_at > datetime('now')", (client_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None
    except:
        return None

def clear_active_signal_db(client_id: str):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM active_signals WHERE client_id=?", (client_id,))
    conn.commit()
    conn.close()

# =============================================================================
# APEX CLIENT WITH EXTERNAL ZK SIGNER
# =============================================================================
SYMBOL_INFO = {"BTC-USDT": {"pair_id": 50001, "price_step": "0.1", "size_step": "0.001"},
               "ETH-USDT": {"pair_id": 50002, "price_step": "0.01", "size_step": "0.01"},
               "SOL-USDT": {"pair_id": 50003, "price_step": "0.001", "size_step": "0.1"}}

def _amount_to_precision(value: float, step: str = "0.001") -> str:
    step_d = Decimal(step)
    v = (Decimal(str(value)) // step_d) * step_d
    return format(v.quantize(step_d), "f")

def _price_to_precision(value: float, step: str = "0.1") -> str:
    step_d = Decimal(step)
    v = (Decimal(str(value)) / step_d).quantize(Decimal(0), rounding="ROUND_HALF_EVEN") * step_d
    return format(v.quantize(step_d), "f")

class ApexClient:
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.creds = None
        self.account_id = None

    async def _load_creds(self):
        if not self.creds:
            self.creds = get_client_creds(self.client_id)
            if not self.creds or not self.creds.get("apex_key"):
                raise ValueError("Apex credentials missing")
        if not self.account_id:
            self.account_id = self.creds.get("apex_account_id")
            if not self.account_id:
                await self._fetch_account_id()

    async def _fetch_account_id(self):
        data = await self._request("GET", "/api/v3/account")
        acc = data.get("data") or data
        self.account_id = str(acc.get("id") or acc.get("accountId"))
        if self.account_id:
            update_client(self.client_id, {"apex_account_id": self.account_id})

    async def _request(self, method: str, endpoint: str, json_data=None, form_data=None, retries=2):
        await self._load_creds()
        ts = str(int(time.time() * 1000))
        
        if form_data:
            body_str = '&'.join(f"{k}={v}" for k, v in sorted(form_data.items()) if v is not None)
            content_type = "application/x-www-form-urlencoded"
        elif json_data and method.upper() != "GET":
            body_str = json.dumps(json_data)
            content_type = "application/json"
        else:
            body_str = ""
            content_type = "application/json"

        sig = base64.b64encode(
            hmac.new(self.creds["apex_secret"].encode(), 
                     (ts + method.upper() + endpoint + body_str).encode(), 
                     hashlib.sha256).digest()
        ).decode()

        headers = {
            "APEX-API-KEY": self.creds["apex_key"],
            "APEX-PASSPHRASE": self.creds.get("apex_passphrase", ""),
            "APEX-TIMESTAMP": ts,
            "APEX-SIGNATURE": sig,
            "Content-Type": content_type
        }

        async with httpx.AsyncClient(timeout=15) as client:
            for attempt in range(retries + 1):
                try:
                    if method.upper() == "GET":
                        resp = await client.get(APEX_REST_BASE + endpoint, headers=headers)
                    elif form_data:
                        resp = await client.post(APEX_REST_BASE + endpoint, content=body_str, headers=headers)
                    else:
                        resp = await client.request(method, APEX_REST_BASE + endpoint, json=json_data, headers=headers)
                    
                    if resp.status_code == 429:
                        await asyncio.sleep(1 * (attempt + 1))
                        continue
                    if resp.status_code != 200:
                        print(f"Apex {method} {endpoint} failed: {resp.text[:500]}")
                        return {"error": resp.text, "status": resp.status_code}
                    return resp.json()
                except Exception as e:
                    if attempt == retries:
                        print(f"Request error: {e}")
                        return {"error": str(e), "status": 500}
                    await asyncio.sleep(0.5 * (attempt + 1))

    async def _call_external_signer(self, order_to_sign: dict) -> str:
        """Ask the external ZK signing service to sign the order."""
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    f"{ZK_SIGNER_URL}/sign",
                    json={"omni_secret": self.creds["apex_omni"], "order": order_to_sign},
                    headers={"Content-Type": "application/json"}
                )
                resp.raise_for_status()
                return resp.json()["signature"]
        except Exception as e:
            raise HTTPException(502, f"External ZK signer failed: {str(e)}")

    async def place_order(self, symbol: str, side: str, size: float, price: Optional[float] = None,
                          tp_price=None, sl_price=None, order_type="LIMIT") -> Dict:
        await self._load_creds()
        sym_info = SYMBOL_INFO.get(symbol, SYMBOL_INFO["BTC-USDT"])
        
        size_str = _amount_to_precision(size, sym_info["size_step"])
        price_str = _price_to_precision(price or 0, sym_info["price_step"])
        
        if order_type.upper() == "MARKET" and not price:
            worst = await self._request("GET", f"/api/v3/get-worst-price?symbol={symbol}&side={side.upper()}")
            price_str = worst.get("data", {}).get("worstPrice") or price_str

        client_oid = f"sv_{int(time.time()*1000)}_{uuid.uuid4().hex[:8]}"
        expiry = int(time.time() + 28 * 24 * 3600)

        # Build order payload for ZK signer (same format as before)
        order_to_sign = {
            "accountId": int(self.account_id),
            "slotId": client_oid,
            "nonce": client_oid,
            "pairId": sym_info["pair_id"],
            "size": size_str,
            "price": price_str,
            "direction": side.upper(),
            "makerFeeRate": "0.0002",
            "takerFeeRate": "0.0005"
        }

        # Get signature from external service
        zk_sig = await self._call_external_signer(order_to_sign)

        body = {
            "symbol": symbol,
            "side": side.upper(),
            "type": order_type.upper(),
            "size": size_str,
            "price": price_str,
            "expiration": expiry,
            "timeInForce": "GOOD_TIL_CANCEL",
            "clientOrderId": client_oid,
            "signature": zk_sig,
            "brokerId": "6956"
        }
        if tp_price: 
            body["takeProfit"] = _price_to_precision(tp_price, sym_info["price_step"])
        if sl_price: 
            body["stopLoss"] = _price_to_precision(sl_price, sym_info["price_step"])

        result = await self._request("POST", "/api/v3/order", form_data=body)
        
        if result.get("data"):
            order_info = BrokerOrder(
                order_id=client_oid,
                broker_order_id=str(result["data"].get("id")),
                account_id=self.client_id,
                symbol=symbol,
                side=side,
                quantity=float(size_str),
                price=float(price_str),
                status="PLACED"
            )
            await broker_state.update_order(order_info)
            return {"success": True, "order_id": result["data"].get("id")}
        return {"success": False, "error": result.get("msg") or str(result)}

# Global client cache
apex_clients: Dict[str, ApexClient] = {}

async def get_apex_client(client_id: str) -> ApexClient:
    if client_id not in apex_clients:
        apex_clients[client_id] = ApexClient(client_id)
    return apex_clients[client_id]

# ------------------------------------------------------------------------------
# APEX TRANSFER & WITHDRAWAL
# ------------------------------------------------------------------------------
async def apex_transfer(client_id: str, amount: str, asset: str = "USDT", from_account: str = "PERPETUAL", to_account: str = "FUNDING") -> Dict:
    client = await get_apex_client(client_id)
    return await client._request("POST", "/api/v3/account/asset/transfer",
                                 json_data={"amount": amount, "asset": asset,
                                            "from": from_account, "to": to_account})

async def apex_withdraw(client_id: str, amount: str, asset: str, address: str, chain_id: str = "1") -> Dict:
    client = await get_apex_client(client_id)
    return await client._request("POST", "/api/v3/account/withdraw",
                                 json_data={"amount": amount, "asset": asset,
                                            "ethAddress": address, "chainId": chain_id,
                                            "type": "FAST_WITHDRAWAL"})

# =============================================================================
# BACKGROUND SYNC TASK (Perpetual balance)
# =============================================================================
async def broker_sync_loop():
    while True:
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT client_id FROM client_creds WHERE apex_key IS NOT NULL")
            rows = c.fetchall()
            conn.close()

            for row in rows:
                client_id = row["client_id"]
                client = await get_apex_client(client_id)

                try:
                    await client._load_creds()
                except Exception as e:
                    print(f"⚠️ Could not load creds for {client_id}: {e}")
                    continue
                if not client.account_id:
                    print(f"⚠️ No account_id for {client_id}")
                    continue

                # Perpetual balance
                bal_resp = await client._request("GET", "/api/v3/account-balance")
                perp_equity = 0.0
                if not bal_resp.get("error"):
                    bal_data = bal_resp.get("data") or bal_resp
                    perp_equity = float(
                        bal_data.get("perpEquity") or
                        bal_data.get("perpTotalEquity") or
                        bal_data.get("totalEquity") or
                        bal_data.get("equity") or 0
                    )
                if perp_equity == 0:
                    account_resp = await client._request("GET", "/api/v3/account")
                    if not account_resp.get("error"):
                        acc = account_resp.get("data") or account_resp
                        perp_equity = float(acc.get("totalEquity") or acc.get("equity") or 0)

                if perp_equity > 0:
                    balance = AccountBalance(
                        account_id=client_id,
                        total_equity=perp_equity,
                        available=perp_equity,
                        unrealized_pnl=0,
                        realized_pnl=0,
                        margin_used=0
                    )
                    await broker_state.update_balance(balance)
                    print(f"✅ Perpetual balance updated for {client_id}: ${perp_equity:.2f} USDT")
                else:
                    print(f"ℹ️ Zero Perpetual balance for {client_id}")

                # Positions
                account_resp = await client._request("GET", "/api/v3/account")
                if not account_resp.get("error"):
                    acc = account_resp.get("data") or account_resp
                    positions_list = acc.get("positions", []) or []
                    for pos in positions_list:
                        size = float(pos.get("size", 0) or pos.get("quantity", 0))
                        if size == 0:
                            continue
                        position = Position(
                            symbol=pos.get("symbol", ""),
                            side=pos.get("side", "LONG"),
                            quantity=size,
                            entry_price=float(pos.get("entryPrice", 0)),
                            unrealized_pnl=float(pos.get("unrealizedPnl", 0)),
                            realized_pnl=float(pos.get("realizedPnl", 0)),
                            account_id=client_id
                        )
                        await broker_state.update_position(position)

                # Open Orders
                orders_resp = await client._request("GET", "/api/v3/open-orders")
                if not orders_resp.get("error") and orders_resp.get("data"):
                    for ordr in orders_resp.get("data", []):
                        order = BrokerOrder(
                            order_id=ordr.get("clientOrderId") or ordr.get("clientId", str(ordr.get("id"))),
                            broker_order_id=str(ordr.get("id")),
                            account_id=client_id,
                            symbol=ordr.get("symbol", ""),
                            side=ordr.get("side", ""),
                            quantity=float(ordr.get("size", 0)),
                            price=float(ordr.get("price", 0)),
                            status=ordr.get("status", "UNKNOWN"),
                            filled_quantity=float(ordr.get("filledSize", 0))
                        )
                        await broker_state.update_order(order)

            await asyncio.sleep(3)
        except Exception as e:
            print(f"❌ Broker sync error: {e}")
            traceback.print_exc()
            await asyncio.sleep(5)

async def fetch_apex_balance(client_id: str) -> Optional[float]:
    try:
        client = await get_apex_client(client_id)
        bal_resp = await client._request("GET", "/api/v3/account-balance")
        if bal_resp.get("error"):
            return None
        data = bal_resp.get("data") or bal_resp
        equity = float(
            data.get("perpEquity") or
            data.get("perpTotalEquity") or
            data.get("totalEquity") or
            data.get("equity") or 0
        )
        return equity if equity > 0 else 0.0
    except Exception as e:
        print(f"❌ fetch_apex_balance exception: {e}")
        return None

# =============================================================================
# OKX API FUNCTIONS
# =============================================================================
async def get_okx_klines(symbol: str, timeframe: str = "1h", limit: int = 300) -> List[Dict]:
    okx_symbol = SYMBOL_TO_OKX.get(symbol, "BTC-USDT-SWAP")
    timeframe_map = {
        "1m": "1m", "5m": "5m", "15m": "15m", "30m": "30m",
        "1h": "1H", "4h": "4H", "1d": "1D", "1w": "1W"
    }
    bar = timeframe_map.get(timeframe, "1H")
    url = f"{OKX_REST_BASE}/api/v5/market/candles"
    params = {"instId": okx_symbol, "bar": bar, "limit": str(limit)}
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(url, params=params)
        if resp.status_code != 200:
            raise Exception(f"OKX API error: {resp.status_code} - {resp.text}")
        data = resp.json()
        if data.get("code") != "0":
            raise Exception(f"OKX error code {data.get('code')}: {data.get('msg')}")
        candles_data = data.get("data", [])
        candles = []
        for candle in reversed(candles_data):
            candles.append({
                "time": int(int(candle[0]) / 1000),
                "open": float(candle[1]),
                "high": float(candle[2]),
                "low": float(candle[3]),
                "close": float(candle[4]),
                "volume": float(candle[5])
            })
        return candles

# =============================================================================
# OKX WEBSOCKET ORDER BOOK
# =============================================================================
class OKXOrderBookManager:
    def __init__(self):
        self.orderbooks = {}
        self.broadcast_levels = 20
        self.ws = None
        self.reconnect_delay = 1
        self.max_reconnect_delay = 30
        self.running = True

    async def connect_and_subscribe(self):
        try:
            self.ws = await websockets.connect(OKX_WS_URL, ping_interval=20, ping_timeout=10, close_timeout=5)
            print("✅ Connected to OKX WebSocket")
            subscribe_args = [{"channel": "books", "instId": SYMBOL_TO_OKX[sym]} for sym in SUPPORTED_SYMBOLS]
            await self.ws.send(json.dumps({"op": "subscribe", "args": subscribe_args}))
            print(f"📚 Subscribed to order books for {SUPPORTED_SYMBOLS}")
            self.reconnect_delay = 1
            return True
        except Exception as e:
            print(f"❌ WebSocket connection failed: {e}")
            return False

    async def process_messages(self):
        if not self.ws:
            return
        try:
            async for message in self.ws:
                try:
                    data = json.loads(message)
                    if "arg" in data and data["arg"].get("channel") == "books":
                        inst_id = data["arg"]["instId"]
                        symbol = next((sym for sym, okx_id in SYMBOL_TO_OKX.items() if okx_id == inst_id), None)
                        if not symbol:
                            continue
                        book_data = data.get("data", [{}])[0]
                        action = book_data.get("action", "")
                        if symbol not in self.orderbooks:
                            self.orderbooks[symbol] = {"bids": {}, "asks": {}, "seq_id": 0}
                        book = self.orderbooks[symbol]
                        if action == "snapshot":
                            book["bids"] = {float(b[0]): float(b[1]) for b in book_data.get("bids", [])}
                            book["asks"] = {float(a[0]): float(a[1]) for a in book_data.get("asks", [])}
                            book["seq_id"] = int(book_data.get("seqId", 0))
                        elif action == "update":
                            for bid in book_data.get("bids", []):
                                price = float(bid[0]); size = float(bid[1])
                                if size == 0:
                                    book["bids"].pop(price, None)
                                else:
                                    book["bids"][price] = size
                            for ask in book_data.get("asks", []):
                                price = float(ask[0]); size = float(ask[1])
                                if size == 0:
                                    book["asks"].pop(price, None)
                                else:
                                    book["asks"][price] = size
                            if "seqId" in book_data:
                                book["seq_id"] = int(book_data["seqId"])
                        if action in ("snapshot", "update"):
                            sorted_bids = sorted(book["bids"].items(), key=lambda x: x[0], reverse=True)[:self.broadcast_levels]
                            sorted_asks = sorted(book["asks"].items(), key=lambda x: x[0])[:self.broadcast_levels]
                            top_bids = [[p, q] for p, q in sorted_bids]
                            top_asks = [[p, q] for p, q in sorted_asks]
                            last_price = top_bids[0][0] if top_bids else 0
                            latest_prices[symbol] = last_price
                            orderbook_cache[symbol] = {"bids": top_bids, "asks": top_asks, "last_price": last_price, "timestamp": time.time()}
                            if websocket_connections:
                                broadcast_data = {"type": "orderbook", "symbol": symbol, "last_price": last_price, "bids": top_bids, "asks": top_asks}
                                disconnected = []
                                for ws_client in websocket_connections:
                                    try:
                                        await ws_client.send_json(broadcast_data)
                                    except:
                                        disconnected.append(ws_client)
                                for ws_client in disconnected:
                                    if ws_client in websocket_connections:
                                        websocket_connections.remove(ws_client)
                    elif "event" in data:
                        if data["event"] == "subscribe":
                            print(f"✅ Subscribed to {data.get('arg', {})}")
                        elif data["event"] == "error":
                            print(f"❌ Subscription error: {data}")
                except:
                    continue
        except websockets.exceptions.ConnectionClosed:
            print("⚠️ WebSocket connection closed")
        except Exception as e:
            print(f"⚠️ WebSocket error: {e}")

    async def start(self):
        while self.running:
            try:
                if await self.connect_and_subscribe():
                    await self.process_messages()
                    if self.ws:
                        try: await self.ws.close()
                        except: pass
                        self.ws = None
                print(f"🔄 Reconnecting in {self.reconnect_delay} seconds...")
                await asyncio.sleep(self.reconnect_delay)
                self.reconnect_delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)
            except Exception as e:
                print(f"❌ Fatal error in OKX WebSocket manager: {e}")
                await asyncio.sleep(self.reconnect_delay)
                self.reconnect_delay = min(self.reconnect_delay * 2, self.max_reconnect_delay)

    def stop(self):
        self.running = False
        if self.ws:
            asyncio.create_task(self.ws.close())

# =============================================================================
# PINESCRIPT ENGINE
# =============================================================================
class PineScriptEngine:
    def __init__(self, script_code: str, symbol: str, timeframe: str):
        self.code = script_code
        self.symbol = symbol
        self.timeframe = timeframe
        self.indicator_name = self._extract_indicator_name()
        self.inputs = self._extract_inputs()

    def _extract_indicator_name(self) -> str:
        match = re.search(r'indicator\("([^"]+)"', self.code)
        return match.group(1) if match else "Unnamed Indicator"

    def _extract_inputs(self) -> Dict[str, Any]:
        inputs = {}
        pattern = r'input\.int\((\d+),\s*"([^"]+)"\)'
        for match in re.finditer(pattern, self.code):
            inputs[match.group(2)] = int(match.group(1))
        return inputs

    def evaluate_on_candles(self, candles: List[Dict]) -> Dict[str, Any]:
        closes = [c["close"] for c in candles]
        length = self.inputs.get("Length", 14)
        rsi_values = self._rsi(closes, length) if "rsi" in self.code.lower() else []
        signals = []
        for i in range(1, len(closes)):
            if rsi_values and i < len(rsi_values):
                if rsi_values[i] > 70:
                    signals.append({"time": candles[i]["time"], "action": "SELL", "price": closes[i],
                                    "strength": min(1.0, (rsi_values[i] - 70) / 30)})
                elif rsi_values[i] < 30:
                    signals.append({"time": candles[i]["time"], "action": "BUY", "price": closes[i],
                                    "strength": min(1.0, (30 - rsi_values[i]) / 30)})
        return {"values": {"rsi": rsi_values}, "signals": signals}

    def _rsi(self, prices: List[float], period: int = 14) -> List[float]:
        if len(prices) < period + 1:
            return [50.0] * len(prices)
        deltas = [prices[i] - prices[i-1] for i in range(1, len(prices))]
        rsi = [50.0] * period
        for i in range(period, len(prices)):
            gains = [d for d in deltas[i-period:i] if d > 0]
            losses = [-d for d in deltas[i-period:i] if d < 0]
            avg_gain = sum(gains) / period if gains else 0
            avg_loss = sum(losses) / period if losses else 0
            rs = avg_gain / avg_loss if avg_loss != 0 else 100
            rsi_val = 100 - (100 / (1 + rs))
            rsi.append(rsi_val)
        return rsi

# =============================================================================
# EA CONSUMER LOOP – uses real Perpetual balance
# =============================================================================
async def ea_consumer_loop(client_id: str):
    client = get_client(client_id)
    if not client:
        return
    while client_id in active_ea_consumers:
        try:
            signal = get_active_signal_db(client_id)
            if signal:
                print(f"EA: signal {signal['action']} for {client_id}")

                balances = await broker_state.get_balances()
                balance_obj = next((b for b in balances if b.account_id == client_id), None)
                real_equity = balance_obj.total_equity if balance_obj else None

                if not real_equity or real_equity <= 0:
                    real_equity = await fetch_apex_balance(client_id)
                    if real_equity and real_equity > 0:
                        await broker_state.update_balance(AccountBalance(
                            account_id=client_id,
                            total_equity=real_equity,
                            available=real_equity,
                            unrealized_pnl=0,
                            realized_pnl=0,
                            margin_used=0
                        ))
                        print(f"EA: Direct fetch – Perp equity = {real_equity} USDT")
                    else:
                        print(f"EA: Still no Perp balance for {client_id}, skipping")
                        await asyncio.sleep(10)
                        continue

                asset_percent = client.get("asset_percent", 10.0)
                risk_amount = real_equity * (asset_percent / 100.0)
                size = risk_amount / signal["price"]
                size = round(size, 3)
                if size <= 0:
                    print(f"EA: Calculated size zero for {client_id}, skipping")
                    await asyncio.sleep(10)
                    continue

                tp_percent = client.get("tp", 2.0)
                sl_percent = client.get("sl", 1.0)
                if signal["action"].upper() == "BUY":
                    tp_price = signal["price"] * (1 + tp_percent / 100.0)
                    sl_price = signal["price"] * (1 - sl_percent / 100.0)
                else:
                    tp_price = signal["price"] * (1 - tp_percent / 100.0)
                    sl_price = signal["price"] * (1 + sl_percent / 100.0)

                apex_client = await get_apex_client(client_id)
                result = await apex_client.place_order(
                    signal["symbol"], signal["action"], size, signal["price"],
                    tp_price=tp_price, sl_price=sl_price
                )

                log_signal(client_id, signal["action"], signal["strength"],
                           result.get("success", False), source="ea_consumer")
                if result.get("success"):
                    log_trade(client_id, {"symbol": signal["symbol"], "side": signal["action"],
                                          "size": size, "price": signal["price"], "status": "PLACED",
                                          "order_id": result.get("order_id"), "pnl": 0})
                await asyncio.sleep(30)
            else:
                await asyncio.sleep(5)
        except Exception as e:
            print(f"EA error: {e}")
            traceback.print_exc()
            await asyncio.sleep(10)

def start_ea_for_client(client_id: str):
    if client_id in active_ea_consumers and not active_ea_consumers[client_id].done():
        return
    task = asyncio.create_task(ea_consumer_loop(client_id))
    active_ea_consumers[client_id] = task

def stop_ea_for_client(client_id: str):
    if client_id in active_ea_consumers:
        active_ea_consumers[client_id].cancel()
        del active_ea_consumers[client_id]

# =============================================================================
# FASTAPI APP – LIFESPAN
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    okx_manager = OKXOrderBookManager()
    ws_task = asyncio.create_task(okx_manager.start())
    sync_task = asyncio.create_task(broker_sync_loop())
    print("="*60)
    print("🚀 SilverVeil Trading Terminal - EXTERNAL ZK SIGNER")
    print(f"📍 http://localhost:{PORT}")
    print("✅ Real OKX order book + chart data")
    print("✅ All orders signed via external ZK service")
    print("✅ EA uses real Perpetual balance")
    print("="*60)
    yield
    okx_manager.stop()
    ws_task.cancel()
    sync_task.cancel()
    for task in active_ea_consumers.values():
        task.cancel()

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ------------------------------------------------------------------------------
# WEBSOCKET ENDPOINTS
# ------------------------------------------------------------------------------
@app.websocket("/ws")
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str = "default"):
    await websocket.accept()
    websocket_connections.append(websocket)
    try:
        for sym, ob in orderbook_cache.items():
            if ob and "bids" in ob and "asks" in ob:
                await websocket.send_json({"type": "orderbook", "symbol": sym, "last_price": ob.get("last_price", 0),
                                           "bids": ob.get("bids", []), "asks": ob.get("asks", [])})
        while True:
            await asyncio.sleep(30)
            try:
                await websocket.send_json({"type": "ping"})
            except:
                break
    except WebSocketDisconnect:
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)
    except Exception as e:
        if websocket in websocket_connections:
            websocket_connections.remove(websocket)

@app.websocket("/ws/trading")
async def trading_websocket(websocket: WebSocket):
    await websocket.accept()
    async def send_update(msg):
        try:
            await websocket.send_json(msg)
        except:
            pass
    broker_state.add_subscriber(send_update)
    try:
        await websocket.send_json({
            "type": "initial_state",
            "data": {
                "orders": [o.dict() for o in await broker_state.get_orders()],
                "positions": [p.dict() for p in await broker_state.get_positions()],
                "balances": [b.dict() for b in await broker_state.get_balances()]
            }
        })
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        broker_state.remove_subscriber(send_update)

# ------------------------------------------------------------------------------
# BROKER STATE ENDPOINTS
# ------------------------------------------------------------------------------
@app.get("/api/broker/orders")
async def broker_orders(client_id: str = None):
    orders = await broker_state.get_orders()
    if client_id:
        orders = [o for o in orders if o.account_id == client_id]
    return [o.dict() for o in orders]

@app.get("/api/broker/positions")
async def broker_positions(client_id: str = None):
    positions = await broker_state.get_positions()
    if client_id:
        positions = [p for p in positions if p.account_id == client_id]
    return [p.dict() for p in positions]

@app.get("/api/broker/balances")
async def broker_balances(client_id: str = None):
    balances = await broker_state.get_balances()
    if client_id:
        balances = [b for b in balances if b.account_id == client_id]
    return [b.dict() for b in balances]

@app.get("/api/broker/status")
async def broker_status():
    return {"connected": True, "sync_active": True}

# ------------------------------------------------------------------------------
# CHART DATA
# ------------------------------------------------------------------------------
@app.get("/api/chart/data")
async def get_chart_data(symbol: str, timeframe: str = "1h", limit: int = 300):
    try:
        candles = await get_okx_klines(symbol, timeframe, limit)
        if not candles:
            raise HTTPException(status_code=404, detail="No kline data from OKX")
        return {"data": candles, "source": "okx"}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch chart data: {str(e)}")

# ------------------------------------------------------------------------------
# PINESCRIPT COMPILE
# ------------------------------------------------------------------------------
@app.post("/api/pine/compile")
async def compile_pine_script(script: PineScriptCreate):
    try:
        candles = await get_okx_klines(script.symbol, "1h", 100)
        if not candles:
            raise HTTPException(status_code=404, detail="No market data from OKX")
        engine = PineScriptEngine(script.code, script.symbol, script.timeframe)
        result = engine.evaluate_on_candles(candles)
        script_id = save_pine_script_to_db(script.client_id, script.name, script.code)
        if result["signals"]:
            sig = result["signals"][-1]
            set_active_signal_db(script.client_id, sig["action"], sig["strength"], sig["price"], script.symbol, "apex")
            log_signal(script.client_id, sig["action"], sig["strength"], False, source="pinescript_compile")
        return {"success": True, "script_id": script_id, "signals": result["signals"], "indicator": engine.indicator_name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to compile script: {str(e)}")

# ------------------------------------------------------------------------------
# CLIENTS API
# ------------------------------------------------------------------------------
@app.post("/api/clients")
async def create_client(client: ClientCreate):
    if get_client(client.client_id):
        raise HTTPException(400, "Client ID already exists")
    now = datetime.now().isoformat()
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO clients (id, name, created_at, modified_at, leverage, tp, sl, asset_percent, profit_percent)
                 VALUES (?,?,?,?,?,?,?,?,?)''',
               (client.client_id, client.name, now, now, client.leverage, client.tp, client.sl,
                client.asset_percent, client.profit_percent))
    conn.commit()
    conn.close()
    save_client_creds(client.client_id, client.model_dump())
    return {"success": True, "client_id": client.client_id}

@app.get("/api/clients")
async def list_clients():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM clients")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"clients": rows}

@app.get("/api/clients/{client_id}")
async def get_client_detail(client_id: str):
    client = get_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    creds = get_client_creds(client_id)
    return {"client": client, "credentials": creds or {}}

@app.put("/api/clients/{client_id}")
async def edit_client(client_id: str, update: ClientUpdate):
    if not get_client(client_id):
        raise HTTPException(404, "Client not found")
    try:
        data = {k: v for k, v in update.model_dump().items() if v is not None}
        update_client(client_id, data)
        return {"success": True}
    except Exception as e:
        print(f"❌ Edit client error: {e}")
        traceback.print_exc()
        raise HTTPException(500, f"Update failed: {str(e)}")

# ------------------------------------------------------------------------------
# TRADE ENDPOINT
# ------------------------------------------------------------------------------
@app.post("/api/trade")
async def trade(req: TradeRequest):
    if not get_client(req.client_id):
        raise HTTPException(404, "Client not found")
    apex_client = await get_apex_client(req.client_id)
    result = await apex_client.place_order(
        req.symbol, req.side, req.size, req.price,
        tp_price=req.tp, sl_price=req.sl
    )
    log_trade(req.client_id, {"symbol": req.symbol, "side": req.side, "size": req.size, "price": req.price,
                              "status": "PLACED" if result.get("success") else "FAILED",
                              "order_id": result.get("order_id")})
    return result

# ------------------------------------------------------------------------------
# EA UPLOAD
# ------------------------------------------------------------------------------
@app.post("/api/ea/upload")
async def upload_ea(client_id: str = Form(...), file: UploadFile = File(...)):
    if not get_client(client_id):
        raise HTTPException(404, "Client not found")
    if not file.filename.endswith('.py'):
        raise HTTPException(400, "Only Python .py files allowed")
    safe_name = f"{client_id}_{int(time.time())}_{file.filename}"
    path = os.path.join(EA_DIR, safe_name)
    content = await file.read()
    with open(path, "wb") as f:
        f.write(content)
    ea_id = str(uuid.uuid4())[:8]
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("UPDATE ea_files SET is_active=0 WHERE client_id=?", (client_id,))
    c.execute("INSERT INTO ea_files (id,client_id,name,file_path,uploaded_at,is_active) VALUES (?,?,?,?,?,1)",
              (ea_id, client_id, file.filename, path, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return {"success": True, "ea_id": ea_id, "filename": file.filename}

@app.get("/api/ea/{client_id}")
async def get_ea(client_id: str):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM ea_files WHERE client_id=? AND is_active=1 ORDER BY uploaded_at DESC LIMIT 1", (client_id,))
    row = c.fetchone()
    conn.close()
    return {"ea": dict(row) if row else None}

# ------------------------------------------------------------------------------
# PINE SCRIPT SAVE / LIST / GET
# ------------------------------------------------------------------------------
@app.post("/api/pine/save")
async def save_pine_script(script: PineScriptCreate):
    if not get_client(script.client_id):
        raise HTTPException(404, "Client not found")
    sid = save_pine_script_to_db(script.client_id, script.name, script.code)
    return {"success": True, "script_id": sid, "message": f"Script '{script.name}' saved"}

@app.get("/api/pine/list/{client_id}")
async def list_pine_scripts(client_id: str):
    scripts = get_all_pine_scripts(client_id)
    return {"scripts": scripts}

@app.get("/api/pine/script/{script_id}")
async def get_pine_script(script_id: str):
    script = get_pine_script_by_id(script_id)
    if not script:
        raise HTTPException(404, "Script not found")
    return {"script": script}

# ------------------------------------------------------------------------------
# SIGNAL, AUTO START/STOP, WITHDRAW, LOGS, HISTORY, BACKTEST
# ------------------------------------------------------------------------------
@app.post("/api/signal")
async def receive_signal(sig: SignalRequest):
    if not get_client(sig.client_id):
        raise HTTPException(404, "Client not found")
    set_active_signal_db(sig.client_id, sig.action, sig.strength, sig.price, sig.symbol, sig.broker)
    log_signal(sig.client_id, sig.action, sig.strength, False, source="pinescript_24h")
    return {"success": True, "message": f"Signal {sig.action} on {sig.symbol} via {sig.broker} active for 24h"}

@app.post("/api/auto/start")
async def start_auto(req: EASettings):
    if not get_client(req.client_id):
        raise HTTPException(404, "Client not found")
    start_ea_for_client(req.client_id)
    return {"success": True, "message": f"Auto trading started for {req.client_id} on {req.symbol}"}

@app.post("/api/auto/stop/{client_id}")
async def stop_auto(client_id: str):
    stop_ea_for_client(client_id)
    return {"success": True, "message": f"Auto trading stopped for {client_id}"}

@app.get("/api/active_signal/{client_id}")
async def get_active_signal(client_id: str):
    sig = get_active_signal_db(client_id)
    return {"active_signal": sig}

@app.post("/api/clear_signal/{client_id}")
async def clear_signal(client_id: str):
    clear_active_signal_db(client_id)
    return {"success": True}

@app.post("/api/transfer/to_perp")
async def transfer_to_perp(client_id: str, amount: str = "ALL"):
    """Transfer USDT from Funding wallet to Perpetual wallet."""
    if not get_client(client_id):
        raise HTTPException(404, "Client not found")
    result = await apex_transfer(client_id, amount, asset="USDT",
                                 from_account="FUNDING", to_account="PERPETUAL")
    return {"success": True, "transfer_result": result}

@app.post("/api/transfer")
async def transfer(req: WithdrawRequest):
    if not get_client(req.client_id):
        raise HTTPException(404, "Client not found")
    result = await apex_transfer(req.client_id, req.amount, req.asset)
    return {"success": True, "transfer_result": result}

@app.post("/api/withdraw")
async def withdraw(req: WithdrawRequest):
    if not get_client(req.client_id):
        raise HTTPException(404, "Client not found")
    creds = get_client_creds(req.client_id)
    if not creds:
        raise HTTPException(404, "Credentials not found")
    wallets = creds.get("withdrawal_wallets", [])
    if req.wallet_index >= len(wallets):
        raise HTTPException(400, f"Wallet index {req.wallet_index} not found")
    address = wallets[req.wallet_index]
    if not address:
        raise HTTPException(400, "Wallet address empty")
    result = await apex_withdraw(req.client_id, req.amount, req.asset, address)
    return {"success": True, "withdraw_result": result}

@app.post("/api/withdraw/full")
async def full_withdraw(req: WithdrawRequest):
    if not get_client(req.client_id):
        raise HTTPException(404, "Client not found")
    creds = get_client_creds(req.client_id)
    if not creds:
        raise HTTPException(404, "Credentials not found")
    wallets = creds.get("withdrawal_wallets", [])
    if req.wallet_index >= len(wallets):
        raise HTTPException(400, "Invalid wallet index")
    address = wallets[req.wallet_index]
    transfer_res = await apex_transfer(req.client_id, req.amount, req.asset)
    if transfer_res.get("error"):
        return {"success": False, "step": "transfer", "error": transfer_res}
    withdraw_res = await apex_withdraw(req.client_id, req.amount, req.asset, address)
    return {"success": True, "transfer_result": transfer_res, "withdraw_result": withdraw_res}

@app.get("/api/logs/{client_id}")
async def get_logs(client_id: str, limit: int = 100):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM trade_logs WHERE client_id=? ORDER BY timestamp DESC LIMIT ?", (client_id, limit))
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"logs": logs}

@app.get("/api/history/{client_id}")
async def get_history(client_id: str, days: int = 30):
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM trade_logs WHERE client_id=? AND timestamp>? ORDER BY timestamp DESC", (client_id, cutoff))
    trades = [dict(r) for r in c.fetchall()]
    total_pnl = sum(t.get("pnl",0) for t in trades)
    conn.close()
    return {"trades": trades, "total_pnl": total_pnl}

@app.get("/api/signals")
async def get_signals(client_id: str = None, limit: int = 50):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if client_id:
        c.execute("SELECT * FROM signal_logs WHERE client_id=? ORDER BY timestamp DESC LIMIT ?", (client_id, limit))
    else:
        c.execute("SELECT * FROM signal_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"signals": rows}

@app.get("/api/positions")
async def get_positions(client_id: str = None):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if client_id:
        c.execute("SELECT * FROM pair_positions WHERE client_id=? AND is_open=1", (client_id,))
    else:
        c.execute("SELECT * FROM pair_positions WHERE is_open=1")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"positions": rows}

@app.get("/api/trades")
async def get_trades(client_id: str = None, limit: int = 50):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if client_id:
        c.execute("SELECT * FROM trade_logs WHERE client_id=? ORDER BY timestamp DESC LIMIT ?", (client_id, limit))
    else:
        c.execute("SELECT * FROM trade_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"trades": rows}

@app.post("/api/backtest/run")
async def run_backtest(symbol: str, strategy: str, start_date: str, end_date: str):
    return {"success": True, "result": {"total_return": 0, "trades": 0, "win_rate": 0}}

@app.get("/health")
async def health():
    return {"status": "online", "version": "36.0-external-zk-signer", "database": DATABASE_PATH, "zk_signer": ZK_SIGNER_URL}

# ------------------------------------------------------------------------------
# FRONTEND HTML (unchanged – full UI)
# ------------------------------------------------------------------------------
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SilverVeil Trading Terminal (External ZK Signer)</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/lightweight-charts@4.1.0/dist/lightweight-charts.standalone.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: 'Inter', sans-serif; background: #0b0e14; color: #d1d4dc; height: 100vh; overflow: hidden; }
        .app { display: flex; flex-direction: column; height: 100%; }
        .top-bar { background: #131722; padding: 8px 16px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #2a2e39; }
        .logo { font-weight: 700; font-size: 1.2rem; color: #00bcd4; }
        .main-panels { display: flex; flex: 1; overflow: hidden; }
        .left-sidebar { width: 260px; background: #131722; border-right: 1px solid #2a2e39; display: flex; flex-direction: column; overflow-y: auto; }
        .nav-item { padding: 12px 16px; cursor: pointer; border-bottom: 1px solid #2a2e39; font-weight: 500; }
        .nav-item:hover, .nav-item.active { background: #1e222d; color: #2962ff; }
        .watchlist-section { margin-top: 20px; padding: 8px 16px; }
        .watchlist-header { font-size: 0.8rem; color: #787b86; margin-bottom: 8px; }
        .watchlist-item { display: flex; justify-content: space-between; padding: 6px 0; cursor: pointer; }
        .watchlist-item:hover { color: #2962ff; }
        .center-panel { flex: 1; display: flex; flex-direction: column; background: #131722; min-width: 0; overflow: hidden; }
        .chart-toolbar { padding: 8px 16px; background: #1e222d; border-bottom: 1px solid #2a2e39; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
        #chartContainer { flex: 1; min-height: 0; }
        .execution-panel { background: #1e222d; border-top: 1px solid #2a2e39; padding: 12px 16px; display: flex; gap: 16px; align-items: center; }
        .long-btn { background: #00bcd4; color: #fff; padding: 8px 24px; border-radius: 8px; border: none; cursor: pointer; font-weight: 700; }
        .short-btn { background: #ef5350; color: #fff; padding: 8px 24px; border-radius: 8px; border: none; cursor: pointer; font-weight: 700; }
        .right-panel { width: 320px; background: #131722; border-left: 1px solid #2a2e39; display: flex; flex-direction: column; overflow-y: auto; }
        .orderbook-header { padding: 12px; font-weight: 600; border-bottom: 1px solid #2a2e39; }
        .orderbook-row { display: flex; justify-content: space-between; padding: 6px 12px; font-size: 0.8rem; }
        .bid { color: #00bcd4; }
        .ask { color: #ef5350; }
        .last-price { padding: 12px; text-align: center; font-size: 1.2rem; font-weight: 600; border-top: 1px solid #2a2e39; }
        .module-panel { display: none; padding: 20px; overflow-y: auto; height: 100%; width: 100%; }
        .module-panel.active { display: block; }
        select, input, button { background: #1e222d; border: 1px solid #2a2e39; color: white; padding: 6px 12px; border-radius: 6px; }
        textarea { width: 100%; background: #1e222d; color: #fff; border: 1px solid #2a2e39; border-radius: 6px; padding: 8px; font-family: monospace; }
        table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-bottom: 1rem; }
        th, td { text-align: left; padding: 6px; border-bottom: 1px solid #2a2e39; }
        th { color: #787b86; font-weight: 500; }
        .broker-panel { margin-bottom: 20px; }
        .broker-title { font-size: 1rem; font-weight: 600; margin-bottom: 10px; color: #00bcd4; }
        .add-client-btn { background: #2962ff; margin-bottom: 12px; width: 100%; }
    </style>
</head>
<body>
<div class="app">
    <div class="top-bar">
        <div class="logo">⚡ SilverVeil (External ZK Signer)</div>
        <div>
            <select id="symbolSelect"></select>
            <select id="timeframeSelect"><option value="1m">1m</option><option value="5m">5m</option><option value="15m">15m</option><option value="1h" selected>1h</option><option value="4h">4h</option><option value="1d">1d</option></select>
        </div>
    </div>
    <div class="main-panels">
        <div class="left-sidebar">
            <div class="nav-item active" data-panel="trade">📈 Trade</div>
            <div class="nav-item" data-panel="clients">👥 Clients</div>
            <div class="nav-item" data-panel="ea">🤖 EA Manager</div>
            <div class="nav-item" data-panel="pine">📜 Pine Editor</div>
            <div class="nav-item" data-panel="withdraw">💰 Withdraw</div>
            <div class="nav-item" data-panel="backtest">📊 Backtesting</div>
            <div class="nav-item" data-panel="logs">📋 Logs</div>
            <div class="nav-item" data-panel="history">📜 History</div>
            <div class="watchlist-section"><div class="watchlist-header">WATCHLIST</div><div id="watchlist"></div></div>
        </div>
        <div id="tradePanel" class="module-panel active" style="display: flex; flex-direction: column; height: 100%;">
            <div class="center-panel" style="display: flex; flex-direction: column; height: 100%;">
                <div class="chart-toolbar">
                    <span id="currentPriceLabel">—</span>
                    <button id="refreshChartBtn">↻</button>
                </div>
                <div id="chartContainer" style="flex: 1; min-height: 200px;"></div>
                <div class="execution-panel">
                    <button class="long-btn" id="longBtn">LONG</button>
                    <button class="short-btn" id="shortBtn">SHORT</button>
                </div>
            </div>
        </div>
        <div id="clientsPanel" class="module-panel">
            <button class="add-client-btn" id="addClientBtn">➕ Add Client</button>
            <div id="clientsList">Loading clients...</div>
        </div>
        <div id="eaPanel" class="module-panel">
            <h3>EA / Auto Trading</h3>
            <div><label>Client ID</label> <input id="eaClientId"></div>
            <div><label>Symbol</label> <select id="eaSymbol"></select></div>
            <div><label>Broker</label> <select id="eaBroker"><option value="apex">Apex</option></select></div>
            <div><button id="startEABtn">▶ Start Auto Trading</button> <button id="stopEABtn">⏹ Stop</button></div>
            <hr>
            <h4>Upload Python EA</h4>
            <input type="file" id="eaFile"><br>
            <button id="uploadEABtn">Upload EA</button>
            <div id="eaStatus"></div>
        </div>
        <div id="pinePanel" class="module-panel">
            <h3>PineScript Editor → Compile & Signal</h3>
            <div><label>Client ID</label> <input id="pineClientId"></div>
            <div><label>Script name</label> <input id="pineScriptName"></div>
            <div><label>Symbol for evaluation</label> <select id="pineSymbol"></select></div>
            <div><label>PineScript Code</label></div>
            <textarea id="pineCode" rows="10" placeholder="//@version=5\nindicator('RSI Strategy')\nlength = input.int(14, 'Length')\nrsi = ta.rsi(close, length)\nif (rsi > 70)\n    strategy.entry('Short', strategy.short)\nif (rsi < 30)\n    strategy.entry('Long', strategy.long)"></textarea><br>
            <button id="compilePineBtn">Compile & Activate Signal (24h)</button>
            <button id="savePineBtn">Save Script Only</button>
            <div id="pineStatus"></div>
            <h4>Saved scripts</h4>
            <div id="savedScriptsList"></div>
        </div>
        <div id="withdrawPanel" class="module-panel">
            <h3>Withdraw Funds</h3>
            <div><label>Client ID</label> <input id="withdrawClientId"></div>
            <div><label>Amount (USDT)</label> <input id="withdrawAmount" placeholder="0.05"></div>
            <div><label>Wallet Index (0-99)</label> <input id="walletIndex" type="number" value="0" min="0" max="99"></div>
            <div><button id="transferBtn">Transfer (Perp → Funding)</button></div>
            <div><button id="withdrawBtn">Withdraw to External</button></div>
            <div><button id="fullWithdrawBtn">Transfer + Withdraw</button></div>
            <div id="withdrawResult"></div>
            <div id="walletList" class="wallet-list">Select client to view wallets</div>
        </div>
        <div id="backtestPanel" class="module-panel"><button id="runBacktestBtn">Run Backtest</button><div id="backtestResult"></div></div>
        <div id="logsPanel" class="module-panel">Logs will appear</div>
        <div id="historyPanel" class="module-panel">History</div>
        <div class="right-panel">
            <div class="orderbook-header">📖 Order Book (OKX)</div>
            <div id="orderbookBids"></div>
            <div id="orderbookAsks"></div>
            <div class="last-price" id="lastPriceDisplay">—</div>

            <div class="orderbook-header" style="margin-top: 16px;">📊 Broker State</div>
            <div style="padding: 8px 12px;">
                <div style="margin-bottom: 12px;"><button id="refreshBrokerBtn" style="width:100%;">⟳ Refresh Now</button></div>
                <div class="broker-panel">
                    <div class="broker-title">📋 Orders</div>
                    <div id="brokerOrdersTable" style="max-height: 200px; overflow-y: auto;">Loading...</div>
                </div>
                <div class="broker-panel">
                    <div class="broker-title">📈 Positions</div>
                    <div id="brokerPositionsTable" style="max-height: 150px; overflow-y: auto;">Loading...</div>
                </div>
                <div class="broker-panel">
                    <div class="broker-title">💰 Balances</div>
                    <div id="brokerBalancesTable" style="max-height: 150px; overflow-y: auto;">Loading...</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Add Client Modal -->
<div id="addClientModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:1000; align-items:center; justify-content:center;">
    <div style="background:#1e222d; padding:20px; border-radius:12px; width:500px; max-width:90%; max-height:90%; overflow-y:auto;">
        <h3>Add Client</h3>
        <div><label>Client ID</label><input id="addClientId" style="width:100%"></div>
        <div><label>Name</label><input id="addName" style="width:100%"></div>
        <div><label>Apex API Key</label><input id="addApexKey" style="width:100%"></div>
        <div><label>Apex Secret</label><input id="addApexSecret" style="width:100%"></div>
        <div><label>Apex Passphrase</label><input id="addApexPass" style="width:100%"></div>
        <div><label>ZK Seeds (apex_omni)</label><input id="addApexOmni" style="width:100%"></div>
        <div><label>Apex Account ID (optional)</label><input id="addApexAccountId" style="width:100%"></div>
        <div><label>Leverage</label><input id="addLeverage" type="number" step="1" value="100" style="width:100%"></div>
        <div><label>TP %</label><input id="addTp" type="number" step="0.1" value="2.0" style="width:100%"></div>
        <div><label>SL %</label><input id="addSl" type="number" step="0.1" value="1.0" style="width:100%"></div>
        <div><label>Asset %</label><input id="addAssetPct" type="number" step="0.1" value="10.0" style="width:100%"></div>
        <div><label>Profit %</label><input id="addProfitPct" type="number" step="0.1" value="0.0" style="width:100%"></div>
        <div><label>Withdrawal Wallets (JSON array)</label><textarea id="addWallets" rows="4" style="width:100%"></textarea></div>
        <div style="margin-top:10px"><button id="confirmAddClientBtn">Create</button> <button id="cancelAddClientBtn">Cancel</button></div>
    </div>
</div>

<!-- Edit Client Modal -->
<div id="editModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:1000; align-items:center; justify-content:center;">
    <div style="background:#1e222d; padding:20px; border-radius:12px; width:500px; max-width:90%; max-height:90%; overflow-y:auto;">
        <h3>Edit Client</h3>
        <div><label>Name</label><input id="editName" style="width:100%"></div>
        <div><label>Apex API Key</label><input id="editApexKey" style="width:100%"></div>
        <div><label>Apex Secret</label><input id="editApexSecret" style="width:100%"></div>
        <div><label>Apex Passphrase</label><input id="editApexPass" style="width:100%"></div>
        <div><label>ZK Seeds</label><input id="editApexOmni" style="width:100%"></div>
        <div><label>Apex Account ID</label><input id="editApexAccountId" style="width:100%"></div>
        <div><label>Leverage</label><input id="editLeverage" type="number" step="1" style="width:100%"></div>
        <div><label>TP %</label><input id="editTp" type="number" step="0.1" style="width:100%"></div>
        <div><label>SL %</label><input id="editSl" type="number" step="0.1" style="width:100%"></div>
        <div><label>Asset %</label><input id="editAssetPct" type="number" step="0.1" style="width:100%"></div>
        <div><label>Profit %</label><input id="editProfitPct" type="number" step="0.1" style="width:100%"></div>
        <div><label>Withdrawal Wallets (JSON array)</label><textarea id="editWallets" rows="4" style="width:100%"></textarea></div>
        <div style="margin-top:10px"><button id="saveEditBtn">Save</button> <button id="cancelEditBtn">Cancel</button></div>
    </div>
</div>

<script>
    let chart, candleSeries, volumeSeries, ws, tradingWs;
    let currentSymbol = 'BTC-USDT', currentTimeframe = '1h';
    let currentEditClientId = null;

    async function loadChart() {
        const res = await fetch(`/api/chart/data?symbol=${currentSymbol}&timeframe=${currentTimeframe}&limit=300`);
        if (!res.ok) {
            document.getElementById('currentPriceLabel').innerText = `Error: ${res.status}`;
            return;
        }
        const data = await res.json();
        if (!data.data) return;
        const candleData = data.data.map(c=>({time:c.time,open:c.open,high:c.high,low:c.low,close:c.close}));
        const volumeData = data.data.map(c=>({time:c.time,value:c.volume,color:c.close>=c.open?'#26a69a':'#ef5350'}));
        if (candleSeries) {
            candleSeries.setData(candleData);
            volumeSeries.setData(volumeData);
        } else {
            const container = document.getElementById('chartContainer');
            chart = LightweightCharts.createChart(container,{width:container.clientWidth,height:container.clientHeight,layout:{backgroundColor:'#131722',textColor:'#d1d4dc'},grid:{vertLines:{color:'#2a2e39'},horzLines:{color:'#2a2e39'}}});
            candleSeries = chart.addCandlestickSeries({upColor:'#26a69a',downColor:'#ef5350'});
            volumeSeries = chart.addHistogramSeries({color:'#26a69a',priceFormat:{type:'volume'},priceScaleId:''});
            chart.priceScale('').applyOptions({scaleMargins:{top:0.8,bottom:0}});
            candleSeries.setData(candleData);
            volumeSeries.setData(volumeData);
            chart.timeScale().fitContent();
            window.addEventListener('resize',()=>chart.resize(container.clientWidth,container.clientHeight));
        }
        if (candleData.length > 0) {
            document.getElementById('currentPriceLabel').innerText = `$${candleData[candleData.length-1].close.toFixed(2)}`;
        }
    }

    function connectOrderBookWebSocket() {
        if (ws && ws.readyState === WebSocket.OPEN) return;
        ws = new WebSocket(`ws://${window.location.host}/ws`);
        ws.onopen = () => console.log('OrderBook WS connected');
        ws.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                if(data.type === 'orderbook'){
                    document.getElementById('lastPriceDisplay').innerText = `$${data.last_price.toFixed(2)}`;
                    if (data.bids && data.bids.length > 0) {
                        let bidsHtml = '<div style="font-size:0.7rem;padding:4px 12px;color:#787b86;">Bids</div>';
                        data.bids.forEach(b => {
                            bidsHtml += `<div class="orderbook-row bid"><span>${parseFloat(b[0]).toFixed(2)}</span><span>${parseFloat(b[1]).toFixed(4)}</span></div>`;
                        });
                        document.getElementById('orderbookBids').innerHTML = bidsHtml;
                    }
                    if (data.asks && data.asks.length > 0) {
                        let asksHtml = '<div style="font-size:0.7rem;padding:4px 12px;color:#787b86;">Asks</div>';
                        data.asks.forEach(a => {
                            asksHtml += `<div class="orderbook-row ask"><span>${parseFloat(a[0]).toFixed(2)}</span><span>${parseFloat(a[1]).toFixed(4)}</span></div>`;
                        });
                        document.getElementById('orderbookAsks').innerHTML = asksHtml;
                    }
                }
            } catch (error) {
                console.error('Error processing orderbook message:', error);
            }
        };
        ws.onerror = (error) => console.error('OrderBook WS error:', error);
        ws.onclose = () => {
            console.log('OrderBook WS disconnected, reconnecting in 5s...');
            setTimeout(connectOrderBookWebSocket, 5000);
        };
    }

    function connectTradingWebSocket() {
        if (tradingWs && tradingWs.readyState === WebSocket.OPEN) return;
        tradingWs = new WebSocket(`ws://${window.location.host}/ws/trading`);
        tradingWs.onopen = () => console.log('Trading WS connected');
        tradingWs.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data);
                if (msg.type === 'initial_state') {
                    updateBrokerDisplays(msg.data);
                } else if (msg.type === 'order_update' || msg.type === 'position_update' || msg.type === 'balance_update') {
                    refreshBrokerState();
                }
            } catch(err) { console.error(err); }
        };
        tradingWs.onclose = () => {
            console.log('Trading WS disconnected, reconnecting in 3s...');
            setTimeout(connectTradingWebSocket, 3000);
        };
    }

    async function refreshBrokerState() {
        try {
            const [ordersRes, positionsRes, balancesRes] = await Promise.all([
                fetch('/api/broker/orders'),
                fetch('/api/broker/positions'),
                fetch('/api/broker/balances')
            ]);
            const orders = await ordersRes.json();
            const positions = await positionsRes.json();
            const balances = await balancesRes.json();
            updateBrokerDisplays({ orders, positions, balances });
        } catch(e) { console.error('Failed to refresh broker state', e); }
    }

    function updateBrokerDisplays(data) {
        let ordersHtml = `<table><tr><th>ID</th><th>Symbol</th><th>Side</th><th>Qty</th><th>Price</th><th>Status</th></tr>`;
        const orders = data.orders || [];
        if (orders.length === 0) ordersHtml += `<tr><td colspan="6">No open orders</td></tr>`;
        else orders.slice(0,10).forEach(o => ordersHtml += `<tr><td>${o.order_id.slice(0,8)}</td><td>${o.symbol}</td><td style="color:${o.side==='BUY'?'#00bcd4':'#ef5350'}">${o.side}</td><td>${o.quantity}</td><td>${o.price?parseFloat(o.price).toFixed(2):'-'}</td><td>${o.status}</td></tr>`);
        ordersHtml += `</table>`;
        document.getElementById('brokerOrdersTable').innerHTML = ordersHtml;

        let posHtml = `<table><tr><th>Symbol</th><th>Side</th><th>Qty</th><th>Entry</th><th>Unrealized PnL</th></tr>`;
        const positions = data.positions || [];
        if (positions.length === 0) posHtml += `<tr><td colspan="5">No open positions</td></tr>`;
        else positions.forEach(p => posHtml += `<tr><td>${p.symbol}</td><td style="color:${p.side==='LONG'?'#00bcd4':'#ef5350'}">${p.side}</td><td>${p.quantity}</td><td>${parseFloat(p.entry_price).toFixed(2)}</td><td style="color:${p.unrealized_pnl>=0?'#00bcd4':'#ef5350'}">${parseFloat(p.unrealized_pnl).toFixed(2)}</td></tr>`);
        posHtml += `</table>`;
        document.getElementById('brokerPositionsTable').innerHTML = posHtml;

        let balHtml = `<table><tr><th>Account</th><th>Total Equity</th><th>Available</th><th>Unrealized PnL</th></tr>`;
        const balances = data.balances || [];
        if (balances.length === 0) balHtml += `<tr><td colspan="4">No balance data yet</td></tr>`;
        else balances.forEach(b => balHtml += `<tr><td>${b.account_id.slice(0,8)}</td><td>$${parseFloat(b.total_equity).toFixed(2)}</td><td>$${parseFloat(b.available).toFixed(2)}</td><td style="color:${b.unrealized_pnl>=0?'#00bcd4':'#ef5350'}">$${parseFloat(b.unrealized_pnl).toFixed(2)}</td></tr>`);
        balHtml += `</table>`;
        document.getElementById('brokerBalancesTable').innerHTML = balHtml;
    }

    function updateSymbol(symbol) { currentSymbol = symbol; loadChart(); }
    function populateSymbolSelects() {
        const symbols = ['BTC-USDT','ETH-USDT','SOL-USDT'];
        const sel = document.getElementById('symbolSelect');
        const eaSym = document.getElementById('eaSymbol');
        const pineSym = document.getElementById('pineSymbol');
        sel.innerHTML = symbols.map(s=>`<option value="${s}">${s}</option>`).join('');
        if(eaSym) eaSym.innerHTML = symbols.map(s=>`<option value="${s}">${s}</option>`).join('');
        if(pineSym) pineSym.innerHTML = symbols.map(s=>`<option value="${s}">${s}</option>`).join('');
        sel.value = 'BTC-USDT';
        if(eaSym) eaSym.value = 'BTC-USDT';
        if(pineSym) pineSym.value = 'BTC-USDT';
        sel.onchange = () => updateSymbol(sel.value);
        currentSymbol = sel.value;
    }

    document.getElementById('timeframeSelect').onchange = () => { currentTimeframe = document.getElementById('timeframeSelect').value; loadChart(); };
    document.getElementById('refreshChartBtn').onclick = loadChart;
    document.getElementById('refreshBrokerBtn').onclick = refreshBrokerState;

    async function loadClients() {
        const res = await fetch('/api/clients');
        const data = await res.json();
        let html = '<h3>Clients</h3><ul>';
        for(let c of data.clients) html += `<li><b>${c.name}</b> (${c.id}) - Lev:${c.leverage}, TP:${c.tp}%, SL:${c.sl}% <button onclick="editClient('${c.id}')">✏️ Edit</button></li>`;
        html += '</ul>';
        document.getElementById('clientsList').innerHTML = html;
    }

    window.editClient = async (clientId) => {
        currentEditClientId = clientId;
        const res = await fetch(`/api/clients/${clientId}`);
        const data = await res.json();
        const client = data.client;
        const creds = data.credentials || {};
        document.getElementById('editName').value = client.name || '';
        document.getElementById('editApexKey').value = creds.apex_key || '';
        document.getElementById('editApexSecret').value = creds.apex_secret || '';
        document.getElementById('editApexPass').value = creds.apex_passphrase || '';
        document.getElementById('editApexOmni').value = creds.apex_omni || '';
        document.getElementById('editApexAccountId').value = creds.apex_account_id || '';
        document.getElementById('editLeverage').value = client.leverage || 100;
        document.getElementById('editTp').value = client.tp || 2;
        document.getElementById('editSl').value = client.sl || 1;
        document.getElementById('editAssetPct').value = client.asset_percent || 10;
        document.getElementById('editProfitPct').value = client.profit_percent || 0;
        document.getElementById('editWallets').value = JSON.stringify(creds.withdrawal_wallets || [], null, 2);
        document.getElementById('editModal').style.display = 'flex';
    };

    function hideEditModal() { document.getElementById('editModal').style.display = 'none'; }
    function hideAddClientModal() { document.getElementById('addClientModal').style.display = 'none'; }

    document.getElementById('saveEditBtn')?.addEventListener('click', async () => {
        if(!currentEditClientId) return;
        let wallets = [];
        try { wallets = JSON.parse(document.getElementById('editWallets').value); if(!Array.isArray(wallets)) wallets = []; } catch(e) { wallets = []; }
        const data = {
            name: document.getElementById('editName').value,
            apex_key: document.getElementById('editApexKey').value,
            apex_secret: document.getElementById('editApexSecret').value,
            apex_passphrase: document.getElementById('editApexPass').value,
            apex_omni: document.getElementById('editApexOmni').value,
            apex_account_id: document.getElementById('editApexAccountId').value,
            leverage: parseFloat(document.getElementById('editLeverage').value),
            tp: parseFloat(document.getElementById('editTp').value),
            sl: parseFloat(document.getElementById('editSl').value),
            asset_percent: parseFloat(document.getElementById('editAssetPct').value),
            profit_percent: parseFloat(document.getElementById('editProfitPct').value),
            withdrawal_wallets: wallets
        };
        try {
            const res = await fetch(`/api/clients/${currentEditClientId}`, { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
            const result = await res.json();
            if(res.ok) { alert('Client updated'); hideEditModal(); loadClients(); }
            else alert('Update failed: ' + (result.detail || result.message || 'Unknown error'));
        } catch(err) { alert('Network error: ' + err.message); }
    });
    document.getElementById('cancelEditBtn')?.addEventListener('click', hideEditModal);
    document.getElementById('addClientBtn')?.addEventListener('click', () => { document.getElementById('addClientModal').style.display = 'flex'; });
    document.getElementById('confirmAddClientBtn')?.addEventListener('click', async () => {
        let wallets = [];
        try { wallets = JSON.parse(document.getElementById('addWallets').value); if(!Array.isArray(wallets)) wallets = []; } catch(e) { wallets = []; }
        const data = {
            client_id: document.getElementById('addClientId').value,
            name: document.getElementById('addName').value,
            apex_key: document.getElementById('addApexKey').value,
            apex_secret: document.getElementById('addApexSecret').value,
            apex_passphrase: document.getElementById('addApexPass').value,
            apex_omni: document.getElementById('addApexOmni').value,
            apex_account_id: document.getElementById('addApexAccountId').value,
            leverage: parseFloat(document.getElementById('addLeverage').value),
            tp: parseFloat(document.getElementById('addTp').value),
            sl: parseFloat(document.getElementById('addSl').value),
            asset_percent: parseFloat(document.getElementById('addAssetPct').value),
            profit_percent: parseFloat(document.getElementById('addProfitPct').value),
            withdrawal_wallets: wallets
        };
        try {
            const res = await fetch('/api/clients', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) });
            const result = await res.json();
            if(res.ok) { alert('Client created'); hideAddClientModal(); loadClients(); }
            else alert('Creation failed: ' + (result.detail || result.message || 'Unknown error'));
        } catch(err) { alert('Network error: ' + err.message); }
    });
    document.getElementById('cancelAddClientBtn')?.addEventListener('click', hideAddClientModal);

    document.getElementById('startEABtn').onclick = async () => {
        const clientId = document.getElementById('eaClientId').value;
        if(!clientId) return alert('Client ID required');
        const res = await fetch('/api/auto/start', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({client_id:clientId, symbol:'BTC-USDT', broker:'apex'}) });
        const data = await res.json(); alert(data.message);
    };
    document.getElementById('stopEABtn').onclick = async () => {
        const clientId = document.getElementById('eaClientId').value;
        if(!clientId) return alert('Client ID required');
        const res = await fetch(`/api/auto/stop/${clientId}`, { method:'POST' }); const data = await res.json(); alert(data.message);
    };
    document.getElementById('uploadEABtn').onclick = async () => {
        const clientId = document.getElementById('eaClientId').value, file = document.getElementById('eaFile').files[0];
        if(!clientId || !file) return alert('Client ID and file required');
        const fd = new FormData(); fd.append('client_id',clientId); fd.append('file',file);
        const res = await fetch('/api/ea/upload', { method:'POST', body:fd });
        const data = await res.json(); document.getElementById('eaStatus').innerHTML = data.success ? `✅ EA uploaded: ${data.filename}` : `❌ Upload failed`;
    };

    async function loadSavedScripts() {
        const cid = document.getElementById('pineClientId').value;
        if(!cid) return;
        const res = await fetch(`/api/pine/list/${cid}`);
        const data = await res.json();
        let html='<ul>';
        for(let s of data.scripts) html+=`<li><b>${s.name}</b> <button onclick="loadScript('${s.id}')">Load</button></li>`;
        html+='</ul>';
        document.getElementById('savedScriptsList').innerHTML = html;
    }
    window.loadScript = async (id) => {
        const res = await fetch(`/api/pine/script/${id}`); const data = await res.json();
        document.getElementById('pineCode').value = data.script.code; document.getElementById('pineScriptName').value = data.script.name;
    };
    document.getElementById('savePineBtn').onclick = async () => {
        const cid = document.getElementById('pineClientId').value, name = document.getElementById('pineScriptName').value, code = document.getElementById('pineCode').value;
        if(!cid||!name) return alert('Client ID and name required');
        const res = await fetch('/api/pine/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid,name,code})});
        const data = await res.json(); alert(data.success?'Saved':'Error'); loadSavedScripts();
    };
    document.getElementById('compilePineBtn').onclick = async () => {
        const cid = document.getElementById('pineClientId').value, name = document.getElementById('pineScriptName').value, code = document.getElementById('pineCode').value, symbol = document.getElementById('pineSymbol').value;
        if(!cid||!name) return alert('Client ID and name required');
        try {
            const res = await fetch('/api/pine/compile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid,name,code,symbol,timeframe:'1h'})});
            if(!res.ok) { const err = await res.text(); alert('Compile error: '+err); return; }
            const data = await res.json(); alert(`Compiled: ${data.signals.length} signals generated. Signal activated for 24h.`); loadSavedScripts();
        } catch(error) { alert('Network error: ' + error.message); }
    };

    async function loadWallets() {
        const clientId = document.getElementById('withdrawClientId').value;
        if(!clientId) return;
        const res = await fetch(`/api/clients/${clientId}`);
        const data = await res.json();
        const wallets = data.credentials?.withdrawal_wallets || [];
        let html = wallets.map((w,i) => `<div class="wallet-item">${i}: ${w.substring(0,20)}...</div>`).join('');
        document.getElementById('walletList').innerHTML = html || 'No wallets stored';
    }
    document.getElementById('withdrawClientId').addEventListener('input', loadWallets);
    document.getElementById('transferBtn').onclick = async () => {
        const clientId = document.getElementById('withdrawClientId').value, amount = document.getElementById('withdrawAmount').value;
        if(!clientId || !amount) return alert('Client ID and amount required');
        const res = await fetch('/api/transfer', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({client_id:clientId, amount}) });
        const data = await res.json(); document.getElementById('withdrawResult').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    };
    document.getElementById('withdrawBtn').onclick = async () => {
        const clientId = document.getElementById('withdrawClientId').value, amount = document.getElementById('withdrawAmount').value, walletIndex = parseInt(document.getElementById('walletIndex').value);
        if(!clientId || !amount) return alert('Client ID and amount required');
        const res = await fetch('/api/withdraw', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({client_id:clientId, amount, wallet_index:walletIndex}) });
        const data = await res.json(); document.getElementById('withdrawResult').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    };
    document.getElementById('fullWithdrawBtn').onclick = async () => {
        const clientId = document.getElementById('withdrawClientId').value, amount = document.getElementById('withdrawAmount').value, walletIndex = parseInt(document.getElementById('walletIndex').value);
        if(!clientId || !amount) return alert('Client ID and amount required');
        const res = await fetch('/api/withdraw/full', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({client_id:clientId, amount, wallet_index:walletIndex}) });
        const data = await res.json(); document.getElementById('withdrawResult').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    };

    async function executeTrade(side) {
        const clientId = prompt('Client ID:'); if(!clientId) return;
        const size = parseFloat(prompt('Size (BTC):','0.001'));
        const price = parseFloat(document.getElementById('lastPriceDisplay').innerText.replace('$',''));
        const tpPct = prompt('Take Profit % (optional, leave blank for none):', '2');
        const slPct = prompt('Stop Loss % (optional, leave blank for none):', '1');
        let tp = null, sl = null;
        if(tpPct && !isNaN(parseFloat(tpPct))) tp = side === 'BUY' ? price * (1 + parseFloat(tpPct)/100) : price * (1 - parseFloat(tpPct)/100);
        if(slPct && !isNaN(parseFloat(slPct))) sl = side === 'BUY' ? price * (1 - parseFloat(slPct)/100) : price * (1 + parseFloat(slPct)/100);
        const res = await fetch('/api/trade',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:clientId,symbol:currentSymbol,side,size,price,tp,sl,dry_run:false})});
        const result = await res.json(); alert(result.success?`Order placed: ${result.order_id}`:`Error: ${result.error}`);
        refreshBrokerState();
    }
    document.getElementById('longBtn').onclick=()=>executeTrade('BUY');
    document.getElementById('shortBtn').onclick=()=>executeTrade('SELL');

    document.querySelectorAll('.nav-item').forEach(item=>{
        item.addEventListener('click',()=>{
            const panel=item.dataset.panel;
            document.querySelectorAll('.module-panel').forEach(p=>p.classList.remove('active'));
            const targetPanel = document.getElementById(panel+'Panel');
            if(targetPanel) targetPanel.classList.add('active');
            document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active')); item.classList.add('active');
            if(panel==='clients') loadClients();
            if(panel==='pine') loadSavedScripts();
            if(panel==='withdraw') loadWallets();
        });
    });

    populateSymbolSelects(); loadChart(); connectOrderBookWebSocket(); connectTradingWebSocket(); loadClients();
    setInterval(refreshBrokerState, 5000);
</script>
</body>
</html>
"""

@app.get("/")
@app.get("/dashboard")
async def serve_ui():
    return HTMLResponse(content=HTML)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)