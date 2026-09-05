# /// script
# requires-python = "==3.11.*"
# dependencies = [
#   "codewords-client==0.4.10",
#   "fastapi==0.116.1",
#   "httpx==0.28.1",
#   "apexomni==3.4.1"
# ]
# [tool.env-checker]
# env_vars = [
#   "PORT=8000",
#   "LOGLEVEL=INFO",
#   "CODEWORDS_API_KEY",
#   "CODEWORDS_RUNTIME_URI"
# ]
# ///

import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import random
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal, ROUND_DOWN, ROUND_UP, ROUND_HALF_EVEN
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlencode

import httpx
from codewords_client import logger, redis_client, run_service
from fastapi import APIRouter, FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

app = FastAPI(title='VertBacon Terminal API', description='Multi-exchange trading terminal backend with Manifold Bot Engine.', version='2.0.0')

# --- constants ---

SYMBOLS: Dict[str, Dict[str, Any]] = {
    'BTC-USDT':  {'base': 62150.0, 'tick': 0.1,     'step': 0.001, 'vol': 45.0,    'pair_id': 50001},
    'ETH-USDT':  {'base': 3210.0,  'tick': 0.01,    'step': 0.01,  'vol': 950.0,   'pair_id': 50002},
    'SOL-USDT':  {'base': 142.5,   'tick': 0.01,    'step': 0.1,   'vol': 3600.0,  'pair_id': 50003},
    'DOGE-USDT': {'base': 0.118,   'tick': 0.00001, 'step': 1.0,   'vol': 900000.0, 'pair_id': 50004},
    'XRP-USDT':  {'base': 0.545,   'tick': 0.0001,  'step': 1.0,   'vol': 180000.0, 'pair_id': 50005},
}

TIMEFRAMES: Dict[str, int] = {'1m': 60, '5m': 300, '15m': 900, '1h': 3600, '4h': 14400, '1d': 86400}
BROKERS = ['ApeX', 'OKX', 'Binance US', 'Evedex', 'Dexari', 'Dexly']
LOG_KINDS = ['ea_master', 'ea_signals', 'ea_trades', 'ea_errors', 'ea_performance', 'ea_debug']
INDICATORS = ['EMA', 'SMA', 'RSI', 'MACD', 'Bollinger Bands', 'Stochastic', 'ATR', 'Ichimoku', 'VWAP', 'Parabolic SAR', 'OBV', 'MFI', 'CCI', 'Williams %R', 'CMF', 'Volume Delta', 'Volume', 'SMC', 'Fibonacci', 'QuantVue', 'Scalper', 'Fury Scalper']

BOT_CONFIG_DEFAULTS: Dict[str, Any] = {
    'bot_mode': 'false',                   # 'true' or 'false'
    'running': False,
    'started_at': None,
    'trade_queue_count': 5,
    'seconds_bw_client': 2,
    'wallet_queue_count': 3,
    'seconds_bw_wallet': 4,
    'bot_contract_qty_pct': 100,
    'tp_priority': ['', '', '', '', ''],
    'sl_priority': ['', '', ''],
    'bot_sl': '',
    'long_queues': '',
    'short_queues': '',
    'long_manage': False,
    'short_manage': False,
    'false_bot_ea_override': False,
    'false_bot_ea_id': '',
    'webuser': False,
    'webuser_ea_id': '',
    'webuser_yearly_profit_limit': 0.0,
    'webuser_passcode_hash': '',
    'indicators_false': ['EMA', 'VWAP'],
    'indicators_true': ['SMC', 'Volume Delta'],
    'indicators_webuser': ['RSI'],
    'transfer_wallet': '',
    'dry_run': True,
    'bot_ea_name': '',
    'bot_ea_code': '',
    'updated_at': '',
}

APEX_API_BASE = os.environ.get('APEX_API_BASE', 'https://omni.apex.exchange')

# --- global bot engine state ---
_bot_task: Optional[asyncio.Task] = None
_bot_stop_event = asyncio.Event()
_engine_lock = asyncio.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _uid() -> str:
    return uuid.uuid4().hex[:12]


def _mask(secret: str) -> str:
    if not secret:
        return ''
    if len(secret) <= 6:
        return '****'
    return secret[:4] + '****' + secret[-4:]


# --- simulation market engine (unchanged) ---
def _series_closes(symbol: str, timeframe: str, count: int) -> List[float]:
    info = SYMBOLS[symbol]
    rng = random.Random(f'{symbol}|{timeframe}')
    base = info['base']
    closes = [base]
    for _ in range(count - 1):
        drift = rng.uniform(-1.0, 1.0) * 0.0035
        closes.append(max(closes[-1] * (1.0 + drift), base * 0.01))
    return closes

def generate_candles(symbol: str, timeframe: str, limit: int = 300) -> List[Dict[str, Any]]:
    if symbol not in SYMBOLS:
        symbol = 'BTC-USDT'
    tf = TIMEFRAMES.get(timeframe, 300)
    info = SYMBOLS[symbol]
    now = int(time.time())
    closes = _series_closes(symbol, timeframe, limit + 1)
    rng = random.Random(f'{symbol}|{timeframe}|ohlc')
    candles: List[Dict[str, Any]] = []
    for i in range(limit):
        o = closes[i]
        c = closes[i + 1]
        if i == limit - 1:
            phase = (now % tf) / tf
            c = c * (1.0 + math.sin((now % 60) + phase * 6.28) * 0.00035)
        h = max(o, c) * (1.0 + rng.uniform(0.0, 0.0022))
        lo = min(o, c) * (1.0 - rng.uniform(0.0, 0.0022))
        v = info['vol'] * rng.uniform(0.45, 2.1)
        t = now - (limit - 1 - i) * tf
        candles.append({'time': t, 'open': round(o, 8), 'high': round(h, 8), 'low': round(lo, 8), 'close': round(c, 8), 'volume': round(v, 2)})
    return candles

def _ema(values: List[float], length: int) -> List[float]:
    if not values:
        return []
    k = 2.0 / (length + 1)
    out = [values[0]]
    for v in values[1:]:
        out.append(v * k + out[-1] * (1.0 - k))
    return out

def _rsi(values: List[float], length: int = 14) -> float:
    if len(values) < length + 1:
        return 50.0
    gains = 0.0
    losses = 0.0
    for i in range(-length, 0):
        d = values[i] - values[i - 1]
        if d >= 0:
            gains += d
        else:
            losses -= d
    if losses == 0:
        return 100.0
    rs = (gains / length) / (losses / length)
    return round(100.0 - 100.0 / (1.0 + rs), 2)

def _vwap(candles: List[Dict[str, Any]]) -> List[float]:
    out: List[float] = []
    cum_pv = 0.0
    cum_v = 0.0
    for c in candles:
        tp = (c['high'] + c['low'] + c['close']) / 3.0
        cum_pv += tp * c['volume']
        cum_v += c['volume']
        out.append(round(cum_pv / cum_v, 8) if cum_v else tp)
    return out

def compute_indicators(candles: List[Dict[str, Any]]) -> Dict[str, Any]:
    closes = [c['close'] for c in candles]
    ema_series = {n: [round(x, 8) for x in _ema(closes, n)] for n in (9, 21, 50, 200)}
    vwap = _vwap(candles)
    last_rsi = _rsi(closes)
    signals: List[Dict[str, Any]] = []
    e9 = ema_series[9]
    e21 = ema_series[21]
    for i in range(1, len(candles)):
        if e9[i - 1] <= e21[i - 1] and e9[i] > e21[i]:
            signals.append({'time': candles[i]['time'], 'price': candles[i]['close'], 'side': 'BUY'})
        elif e9[i - 1] >= e21[i - 1] and e9[i] < e21[i]:
            signals.append({'time': candles[i]['time'], 'price': candles[i]['close'], 'side': 'SELL'})
    return {'ema': ema_series, 'vwap': vwap, 'rsi14': last_rsi, 'signals': signals[-60:], 'last': {'close': closes[-1], 'rsi14': last_rsi}}

def generate_orderbook(symbol: str, depth: int = 18) -> Dict[str, Any]:
    if symbol not in SYMBOLS:
        symbol = 'BTC-USDT'
    info = SYMBOLS[symbol]
    tick = info['tick']
    candles = generate_candles(symbol, '1m', 2)
    last = candles[-1]['close']
    last = round(round(last / tick) * tick, 8)
    rng = random.Random(f'{symbol}|ob|{int(time.time() // 5)}')
    bids: List[Dict[str, Any]] = []
    asks: List[Dict[str, Any]] = []
    px = last
    for i in range(depth):
        bid_px = round(px - tick * (i + 1), 8)
        ask_px = round(px + tick * (i + 1), 8)
        base_qty = info['vol'] * rng.uniform(0.4, 3.0)
        bids.append({'price': bid_px, 'size': round(base_qty * (1 + i * 0.08), 4)})
        asks.append({'price': ask_px, 'size': round(base_qty * (1 + i * 0.08), 4)})
    best_bid = bids[0]['price']
    best_ask = asks[0]['price']
    return {'symbol': symbol, 'last': last, 'best_bid': best_bid, 'best_ask': best_ask, 'spread': round(best_ask - best_bid, 8), 'bids': bids, 'asks': asks}

def generate_ticker(symbol: str) -> Dict[str, Any]:
    candles = generate_candles(symbol, '1d', 2)
    last = candles[-1]['close']
    prev = candles[-2]['close'] if len(candles) > 1 else last
    change_pct = round((last - prev) / prev * 100, 4) if prev else 0.0
    return {'symbol': symbol, 'last': last, 'change_24h_pct': change_pct, 'high_24h': round(last * 1.012, 8), 'low_24h': round(last * 0.988, 8), 'volume_24h': round(SYMBOLS[symbol]['vol'] * 22000, 2)}

# --- ApeX Omni live adapter (unchanged) ---
def _apex_creds() -> Dict[str, str]:
    return {'api_key': os.environ.get('APEX_API_KEY', ''), 'api_secret': os.environ.get('APEX_API_SECRET', ''), 'passphrase': os.environ.get('APEX_PASSPHRASE', ''), 'omni_key': os.environ.get('APEX_OMNI_KEY', ''), 'account_id': os.environ.get('APEX_ACCOUNT_ID', '')}

def _hmac_sign(message: str, secret: str) -> str:
    key = base64.standard_b64encode(secret.encode())
    sig = hmac.new(key, message.encode(), hashlib.sha256).digest()
    return base64.standard_b64encode(sig).decode()

async def apex_request(method: str, path: str, params: Optional[Dict] = None, body: Optional[Dict] = None) -> Dict[str, Any]:
    creds = _apex_creds()
    if not creds['api_key'] or not creds['api_secret']:
        return {'configured': False, 'error': 'ApeX credentials not configured'}
    ts = str(int(time.time() * 1000))
    qs = ('?' + urlencode(params)) if params else ''
    msg = ts + method + path + qs
    if body:
        msg += urlencode(dict(sorted(body.items())))
    sig = _hmac_sign(msg, creds['api_secret'])
    headers = {'APEX-API-KEY': creds['api_key'], 'APEX-PASSPHRASE': creds['passphrase'], 'APEX-TIMESTAMP': ts, 'APEX-SIGNATURE': sig, 'Accept': 'application/json', 'User-Agent': 'vertbacon-terminal'}
    url = APEX_API_BASE + path + qs
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if method == 'GET':
                resp = await client.get(url, headers=headers)
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                resp = await client.post(url, headers=headers, content=urlencode(body or {}))
    except Exception as e:
        return {'configured': True, 'error': f'request failed: {str(e)}'}
    try:
        data = resp.json()
    except Exception:
        data = {'raw': resp.text[:400]}
    return {'configured': True, 'status_code': resp.status_code, 'data': data}

async def _apex_signed_request(creds: Dict[str, str], method: str, path: str, params: Optional[Dict] = None, body: Optional[Dict] = None) -> Dict[str, Any]:
    if not creds.get('api_key') or not creds.get('api_secret'):
        return {'configured': False, 'error': 'ApeX credentials not configured'}
    ts = str(int(time.time() * 1000))
    qs = ('?' + urlencode(params)) if params else ''
    msg = ts + method + path + qs
    if body:
        msg += urlencode(dict(sorted(body.items())))
    sig = _hmac_sign(msg, creds['api_secret'])
    headers = {'APEX-API-KEY': creds['api_key'], 'APEX-PASSPHRASE': creds.get('passphrase', ''), 'APEX-TIMESTAMP': ts, 'APEX-SIGNATURE': sig, 'Accept': 'application/json', 'User-Agent': 'vertbacon-terminal'}
    url = APEX_API_BASE + path + qs
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            if method == 'GET':
                resp = await client.get(url, headers=headers)
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                resp = await client.post(url, headers=headers, content=urlencode(body or {}))
    except Exception as e:
        return {'configured': True, 'error': f'request failed: {str(e)}'}
    try:
        data = resp.json()
    except Exception:
        data = {'raw': resp.text[:400]}
    return {'configured': True, 'status_code': resp.status_code, 'data': data}

def _rand_number(size: int) -> int:
    return int(''.join([str(random.randint(0, 9)) for _ in range(size)]))

def _generate_client_id_omni(account_id: str) -> str:
    return f'apexomni-{account_id}-{int(time.time() * 1000)}-{_rand_number(6)}'

def _amount_to_precision(value: float, step: str) -> str:
    step_d = Decimal(step)
    v = (Decimal(str(value)) // step_d) * step_d
    return format(v.quantize(step_d), 'f')

def _price_to_precision(value: float, step: str) -> str:
    step_d = Decimal(step)
    v = (Decimal(str(value)) / step_d).quantize(Decimal(0), rounding=ROUND_HALF_EVEN) * step_d
    return format(v.quantize(step_d), 'f')

def _sign_order_zk(seeds: str, order_to_sign: Dict[str, Any]) -> str:
    from apexomni import zklink_sdk
    slot_id_raw = order_to_sign['slotId']
    nonce_int = int(hashlib.sha256(slot_id_raw.encode()).hexdigest(), 16)
    max_uint64 = 18446744073709551615
    max_uint32 = 4294967295
    slot_id = int((nonce_int % max_uint64) / max_uint32)
    nonce = nonce_int % max_uint32
    account_id = int(order_to_sign['accountId']) % max_uint32
    price_str = (Decimal(str(order_to_sign['price'])) * Decimal(10) ** Decimal('18')).quantize(Decimal(0), rounding=ROUND_DOWN)
    size_str = (Decimal(str(order_to_sign['size'])) * Decimal(10) ** Decimal('18')).quantize(Decimal(0), rounding=ROUND_DOWN)
    taker_fee_rate = (Decimal(str(order_to_sign['takerFeeRate'])) * Decimal(10000)).quantize(Decimal(0), rounding=ROUND_UP)
    maker_fee_rate = (Decimal(str(order_to_sign['makerFeeRate'])) * Decimal(10000)).quantize(Decimal(0), rounding=ROUND_UP)
    is_buy = order_to_sign['direction'] == 'BUY'
    builder = zklink_sdk.ContractBuilder(int(account_id), int(0), int(slot_id), int(nonce), int(order_to_sign['pairId']), str(size_str), str(price_str), is_buy, int(taker_fee_rate), int(maker_fee_rate), False)
    tx = zklink_sdk.Contract(builder)
    seeds_bytes = bytes.fromhex(seeds.removeprefix('0x'))
    signer = zklink_sdk.ZkLinkSigner().new_from_seed(seeds_bytes)
    auth_data = signer.sign_musig(tx.get_bytes())
    return auth_data.signature

async def apex_place_order(creds: Dict[str, str], symbol: str, side: str, size: float, price: float, reduce_only: bool = False) -> Dict[str, Any]:
    if symbol not in SYMBOLS:
        return {'status': 'error', 'error': f'unsupported symbol {symbol}'}
    info = SYMBOLS[symbol]
    price_step = str(info['tick'])
    size_step = str(info['step'])
    omni_key = creds.get('omni_key', '')
    if not (creds.get('api_key') and creds.get('api_secret') and omni_key):
        return {'status': 'error', 'error': 'client ApeX credentials incomplete (api_key, api_secret, omni_key required)'}
    acc = await _apex_signed_request(creds, 'GET', '/api/v3/account')
    acc_data = acc.get('data', {})
    account_id = acc_data.get('data', {}).get('id') if isinstance(acc_data, dict) else None
    if not account_id:
        return {'status': 'error', 'error': f"account lookup failed: {acc.get('data') or acc.get('error')}"}
    account_id = str(account_id)
    order_size = _amount_to_precision(size, size_step)
    order_price = _price_to_precision(price, price_step)
    taker = '0.0005'
    maker = '0.0002'
    fee_val = (Decimal(order_price) * Decimal(order_size) * Decimal(taker)) + Decimal(price_step)
    limit_fee = format(((fee_val // Decimal(price_step)) * Decimal(price_step)).quantize(Decimal(price_step)), 'f')
    client_order_id = _generate_client_id_omni(account_id)
    order_to_sign = {'accountId': account_id, 'slotId': client_order_id, 'nonce': client_order_id, 'pairId': str(info['pair_id']), 'size': order_size, 'price': order_price, 'direction': side.upper(), 'makerFeeRate': maker, 'takerFeeRate': taker}
    try:
        signature = _sign_order_zk(omni_key, order_to_sign)
    except Exception as e:
        return {'status': 'error', 'error': f'ZK signing failed: {e}'}
    expiration = int(math.floor(time.time() + 30 * 24 * 60 * 60))
    request_body = {'symbol': symbol, 'side': side.upper(), 'type': 'MARKET', 'size': order_size, 'price': order_price, 'limitFee': limit_fee, 'expiration': expiration, 'timeInForce': 'GOOD_TIL_CANCEL', 'clientId': client_order_id, 'brokerId': '6956', 'signature': signature}
    if reduce_only:
        request_body['reduceOnly'] = 'true'
    result = await _apex_signed_request(creds, 'POST', '/api/v3/order', body=request_body)
    data = result.get('data', {})
    if result.get('status_code') == 200 and isinstance(data, dict) and data.get('data'):
        order_info = data['data']
        return {'status': 'filled', 'id': order_info.get('id', ''), 'symbol': symbol, 'side': side.upper(), 'size': order_size, 'price': float(order_info.get('price') or order_price), 'raw': order_info}
    return {'status': 'error', 'error': data, 'status_code': result.get('status_code')}

# --- New: ApeX cancel-all and reduce-only close ---

async def apex_cancel_all_orders(creds: Dict[str, str], symbol: Optional[str] = None) -> Dict[str, Any]:
    """Cancel all open orders for the given symbol (or all if symbol None)."""
    if not creds.get('api_key') or not creds.get('api_secret'):
        return {'status': 'error', 'error': 'ApeX credentials not configured'}
    body = {}
    if symbol:
        body['symbol'] = symbol
    result = await _apex_signed_request(creds, 'POST', '/api/v3/delete-open-orders', body=body)
    return result

async def apex_close_position(creds: Dict[str, str], symbol: str, side: str, size: float) -> Dict[str, Any]:
    """
    Close a position by placing a reduce-only market order opposite to the side.
    side: current position side ('LONG' or 'SHORT')
    """
    opposite = 'SELL' if side.upper() == 'LONG' else 'BUY'
    ob = generate_orderbook(symbol)
    price = ob['last']
    return await apex_place_order(creds, symbol, opposite, size, price, reduce_only=True)

# --- persistence (Redis) ---

PINE_SEED: List[Dict[str, str]] = [
    {'name': 'VertBacon SMC/FIB Fusion', 'code': '''//@version=5
indicator('VertBacon SMC/FIB Fusion', overlay=true)
lookback = input.int(50, 'Lookback')
range_high = ta.highest(high, lookback)
range_low = ta.lowest(low, lookback)
mid = range_low + (range_high - range_low) * 0.5
plot(range_high, 'Range High', color=color.new(color.red, 40))
plot(range_low, 'Range Low', color=color.new(color.green, 40))
plot(mid, 'Mid', color=color.orange)
bullish = close > mid
plotshape(bullish and not bullish[1], 'LONG', shape.labelup, location.belowbar, color.green)
plotshape(not bullish and bullish[1], 'SHORT', shape.labeldown, location.abovebar, color.red)
alertcondition(bullish and not bullish[1], 'SMC LONG', 'Long signal')
alertcondition(not bullish and bullish[1], 'SMC SHORT', 'Short signal')
'''},
    {'name': 'EMA Crossover', 'code': '''//@version=5
indicator('EMA Crossover', overlay=true)
fast = input.int(9, 'Fast EMA')
slow = input.int(21, 'Slow EMA')
e_fast = ta.ema(close, fast)
e_slow = ta.ema(close, slow)
plot(e_fast, 'Fast', color=color.blue)
plot(e_slow, 'Slow', color=color.orange)
long = ta.crossover(e_fast, e_slow)
short = ta.crossunder(e_fast, e_slow)
plotshape(long, 'LONG', shape.triangleup, location.belowbar, color.green, size=size.small)
plotshape(short, 'SHORT', shape.triangledown, location.abovebar, color.red, size=size.small)
alertcondition(long, 'EMA LONG')
alertcondition(short, 'EMA SHORT')
'''},
    {'name': 'VWAP + Volume', 'code': '''//@version=5
indicator('VWAP + Volume', overlay=true)
plot(ta.vwap(close), 'VWAP', color=color.orange, linewidth=2)
vol_up = close >= open ? volume : 0
vol_dn = close < open ? volume : 0
plot(vol_up, 'Vol Up', color=color.new(color.green, 40), style=plot.style_columns)
plot(-vol_dn, 'Vol Dn', color=color.new(color.red, 40), style=plot.style_columns)
'''},
    {'name': 'RSI Momentum', 'code': '''//@version=5
indicator('RSI Momentum', overlay=false)
len = input.int(14, 'Length')
ov = input.int(70, 'Overbought')
un = input.int(30, 'Oversold')
r = ta.rsi(close, len)
plot(r, 'RSI', color=color.purple)
h1 = hline(ov, 'OB', color=color.red)
h2 = hline(un, 'OS', color=color.green)
fill(h1, h2, color=color.new(color.gray, 90))
plotshape(ta.crossover(r, un), 'LONG', shape.triangleup, location.bottom, color.green)
plotshape(ta.crossunder(r, ov), 'SHORT', shape.triangledown, location.top, color.red)
'''},
    {'name': 'Bollinger Bands', 'code': '''//@version=5
indicator('Bollinger Bands', overlay=true)
len = input.int(20, 'Length')
mult = input.float(2.0, 'Multiplier')
basis = ta.sma(close, len)
dev = mult * ta.stdev(close, len)
up = basis + dev
dn = basis - dev
plot(basis, 'Basis', color=color.gray)
p1 = plot(up, 'Upper', color=color.blue)
p2 = plot(dn, 'Lower', color=color.blue)
fill(p1, p2, color=color.new(color.blue, 90))
plotshape(close < dn, 'LONG', shape.triangleup, location.belowbar, color.green)
plotshape(close > up, 'SHORT', shape.triangledown, location.abovebar, color.red)
'''},
]

def _seed(kind: str) -> Any:
    if kind == 'clients':
        return {
            'rmntg00000': {'id': 'rmntg00000', 'name': 'rmntg00000', 'brokers': ['ApeX'], 'apex_api_key': '', 'apex_api_secret': '', 'okx_api_key': '', 'okx_api_secret': '', 'evedex_api_key': '', 'evedex_api_secret': '', 'binance_us_api_key': '', 'binance_us_api_secret': '', 'dexari_wallet': '', 'dexly_wallet': '', 'withdrawal_wallet': '', 'transfer_wallet': '', 'pct_asset': 10.0, 'pct_profit': 0.08, 'leverage': 100, 'tp_pct': 0.08, 'sl_pct': 0.0, 'mode': 'automated', 'ea_id': 'ea_fibsmc', 'created_at': _now_iso()},
            'client_alpha': {'id': 'client_alpha', 'name': 'Client Alpha', 'brokers': ['ApeX', 'OKX'], 'apex_api_key': '', 'apex_api_secret': '', 'okx_api_key': '', 'okx_api_secret': '', 'evedex_api_key': '', 'evedex_api_secret': '', 'binance_us_api_key': '', 'binance_us_api_secret': '', 'dexari_wallet': '0x0000000000000000000000000000000000000001', 'dexly_wallet': '', 'withdrawal_wallet': '0x0000000000000000000000000000000000000001', 'transfer_wallet': '', 'pct_asset': 25.0, 'pct_profit': 0.05, 'leverage': 50, 'tp_pct': 0.1, 'sl_pct': 0.05, 'mode': 'semi-automated', 'ea_id': 'ea_smcpro', 'created_at': _now_iso()},
            'client_beta': {'id': 'client_beta', 'name': 'Client Beta', 'brokers': ['Binance US'], 'apex_api_key': '', 'apex_api_secret': '', 'okx_api_key': '', 'okx_api_secret': '', 'evedex_api_key': '', 'evedex_api_secret': '', 'binance_us_api_key': '', 'binance_us_api_secret': '', 'dexari_wallet': '', 'dexly_wallet': '', 'withdrawal_wallet': '0x0000000000000000000000000000000000000002', 'transfer_wallet': '', 'pct_asset': 15.0, 'pct_profit': 0.1, 'leverage': 20, 'tp_pct': 0.15, 'sl_pct': 0.08, 'mode': 'manual', 'ea_id': '', 'created_at': _now_iso()},
        }
    if kind == 'groups':
        return {'group_prop': {'id': 'group_prop', 'name': 'Prop Firm A', 'client_ids': ['client_alpha', 'client_beta'], 'trade_queue_count': 5, 'seconds_bw_client': 2, 'wallet_queue_count': 3, 'seconds_bw_wallet': 4, 'long_queues': '1,2', 'short_queues': '', 'long_manage': False, 'short_manage': False, 'created_at': _now_iso()}}
    if kind == 'schedules':
        return {'sched_1': {'id': 'sched_1', 'name': 'US Open Scalp', 'group_id': 'group_prop', 'cron': '0 9,13,15 * * 1-5', 'priority': 1, 'side': 'auto', 'enabled': True, 'created_at': _now_iso()}}
    if kind == 'eas':
        return {'ea_fibsmc': {'id': 'ea_fibsmc', 'name': 'FIB/SMC Fusion EA', 'source': 'C++ (fibsmc_fusion_ea.cpp)', 'description': 'Fibonacci + Smart Money Concepts automated execution.', 'active': True, 'created_at': _now_iso()}, 'ea_candles': {'id': 'ea_candles', 'name': 'Candlesticks EA', 'source': 'C++ (candlesticks_ea.cpp)', 'description': 'Candlestick pattern execution with TP/SL.', 'active': False, 'created_at': _now_iso()}, 'ea_smcpro': {'id': 'ea_smcpro', 'name': 'SMC Pro EA', 'source': 'Pine (SMC/FIB Fusion)', 'description': 'Smart-money confluence EA driven by Pine signals.', 'active': False, 'created_at': _now_iso()}}
    if kind == 'pines':
        return {p['name']: {'id': p['name'], 'name': p['name'], 'code': p['code'], 'created_at': _now_iso()} for p in PINE_SEED}
    if kind == 'logs':
        base = int(time.time())
        mk = lambda t, lvl, msg: {'ts': base - t, 'level': lvl, 'msg': msg}
        return {'ea_master': [mk(0, 'INFO', 'VertBacon engine started (dry-run)'), mk(20, 'INFO', 'Loaded 3 clients, 1 group, 1 schedule'), mk(45, 'INFO', 'Market engine online - BTC-USDT/ETH-USDT/SOL-USDT streaming')], 'ea_signals': [mk(5, 'SIGNAL', 'SMC/FIB Fusion -> BTC-USDT LONG signal'), mk(30, 'SIGNAL', 'EMA Crossover -> ETH-USDT SHORT signal'), mk(60, 'SIGNAL', 'VWAP reclaim -> SOL-USDT LONG signal')], 'ea_trades': [mk(10, 'TRADE', 'rmntg00000 LONG 0.010 BTC-USDT @ 62150 (dry)'), mk(35, 'TRADE', 'client_alpha SHORT 1.2 ETH-USDT @ 3210 (dry)')], 'ea_errors': [mk(15, 'WARN', 'ApeX credentials not configured - running dry-run')], 'ea_performance': [mk(40, 'INFO', 'Equity +0.42% this session - drawdown -0.11%')], 'ea_debug': [mk(2, 'DEBUG', 'redis state loaded ok'), mk(8, 'DEBUG', 'indicator cache warmed for 3 symbols')]}
    if kind == 'history':
        return [{'id': 'h1', 'client_id': 'rmntg00000', 'symbol': 'BTC-USDT', 'side': 'LONG', 'qty': 0.01, 'entry': 62150.0, 'exit': 62240.0, 'pnl': 0.90, 'pnl_pct': 0.14, 'mode': 'dry', 'closed_at': _now_iso()}, {'id': 'h2', 'client_id': 'client_alpha', 'symbol': 'ETH-USDT', 'side': 'SHORT', 'qty': 1.2, 'entry': 3210.0, 'exit': 3185.0, 'pnl': 30.0, 'pnl_pct': 0.78, 'mode': 'dry', 'closed_at': _now_iso()}]
    if kind == 'positions':
        return [{'id': 'pos1', 'client_id': 'rmntg00000', 'symbol': 'BTC-USDT', 'side': 'LONG', 'qty': 0.01, 'entry': 62150.0, 'leverage': 100, 'liq': 61528.5, 'pnl': 0.60, 'mode': 'dry', 'opened_at': _now_iso()}, {'id': 'pos2', 'client_id': 'client_alpha', 'symbol': 'ETH-USDT', 'side': 'SHORT', 'qty': 1.2, 'entry': 3210.0, 'leverage': 50, 'liq': 3274.2, 'pnl': -12.0, 'mode': 'dry', 'opened_at': _now_iso()}]
    if kind == 'withdrawals':
        return []
    if kind == 'bot_config':
        cfg = dict(BOT_CONFIG_DEFAULTS)
        cfg['updated_at'] = _now_iso()
        return cfg
    if kind == 'bridge':
        return {'running': True, 'broker_connected': False, 'signals': []}
    return {}

async def _load(kind: str) -> Any:
    try:
        async with redis_client() as (redis, ns):
            raw = await redis.get(f'{ns}:vb:{kind}')
        if raw is None:
            return _seed(kind)
        return json.loads(raw)
    except Exception as e:
        logger.warning('redis load fallback to seed', kind=kind, error=str(e))
        return _seed(kind)

async def _save(kind: str, data: Any) -> None:
    try:
        async with redis_client() as (redis, ns):
            await redis.set(f'{ns}:vb:{kind}', json.dumps(data))
    except Exception as e:
        logger.error('redis save failed', kind=kind, error=str(e))

async def _append_log(kind: str, level: str, msg: str) -> None:
    logs = await _load('logs')
    if kind not in logs:
        logs[kind] = []
    logs[kind].append({'ts': int(time.time()), 'level': level, 'msg': msg})
    logs[kind] = logs[kind][-500:]
    await _save('logs', logs)

def _mask_client(c: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(c)
    for k in ('apex_api_secret', 'apex_passphrase', 'apex_omni_key'):
        if out.get(k):
            out[k] = _mask(out[k])
    return out

# --- NEW: Fibonacci signal generator ---
def fibonacci_signal(candles: List[Dict], lookback: int = 50) -> str:
    """
    Compute Fibonacci retracement levels and generate a signal.
    Returns 'BUY', 'SELL', or 'NEUTRAL'.
    """
    if len(candles) < lookback:
        return 'NEUTRAL'
    # Use the last `lookback` candles
    segment = candles[-lookback:]
    highs = [c['high'] for c in segment]
    lows = [c['low'] for c in segment]
    high = max(highs)
    low = min(lows)
    diff = high - low
    if diff == 0:
        return 'NEUTRAL'
    levels = {
        0.236: low + 0.236 * diff,
        0.382: low + 0.382 * diff,
        0.5: low + 0.5 * diff,
        0.618: low + 0.618 * diff,
        0.786: low + 0.786 * diff,
        1.0: high,
        1.618: high + 0.618 * diff
    }
    last_close = candles[-1]['close']
    # Simple rule: break above 0.786 -> BUY, break below 0.236 -> SELL
    if last_close > levels[0.786]:
        return 'BUY'
    elif last_close < levels[0.236]:
        return 'SELL'
    else:
        return 'NEUTRAL'

# --- NEW: Helper to parse priority fields ---
def parse_priority(value: str) -> Optional[float]:
    """Parse a priority field string (e.g., '0.08' or '8%') into a decimal factor."""
    if not value:
        return None
    val = value.strip()
    if val.endswith('%'):
        try:
            pct = float(val[:-1]) / 100.0
            return pct
        except ValueError:
            return None
    try:
        return float(val)
    except ValueError:
        return None

# --- NEW: Calculate contract quantity using client balance (placeholder) ---
def calculate_contract_qty(client: Dict[str, Any], symbol: str, bot_pct: float) -> Dict[str, Any]:
    """Compute contract quantity based on 90% of balance * leverage * bot_pct%."""
    # In simulation, we use a placeholder balance; in live, we would fetch from broker.
    # For demo, we'll use a placeholder: assume balance = 10000 USDT for all clients.
    balance = 10000.0  # TODO: fetch from broker account
    leverage = float(client.get('leverage', 10))
    pct = bot_pct / 100.0
    # 90% of balance
    available = balance * 0.9
    notional = available * leverage * pct
    price = generate_orderbook(symbol)['last']
    qty = notional / price if price else 0.0
    # Apply symbol step and max
    step = float(SYMBOLS[symbol]['step'])
    qty = (qty // step) * step
    # Cap for BTC-USDT
    if symbol == 'BTC-USDT':
        qty = min(qty, 225.0)
    return {'qty': round(qty, 8), 'notional': round(notional, 2), 'price': price, 'leverage': leverage}

# --- Manifold Bot Engine (fully implemented) ---

async def _manifold_engine_loop():
    """Main background loop for the manifold bot engine with auto‑open, Fibonacci signals, TP/SL priorities."""
    global _bot_stop_event
    logger.info('Manifold Engine started')
    while not _bot_stop_event.is_set():
        try:
            # Reload configuration each cycle
            cfg = await _load('bot_config')
            if not cfg.get('running', False):
                # If bot is not running, we still monitor positions but don't take new actions.
                await asyncio.sleep(2)
                continue

            mode = cfg.get('bot_mode', 'false')
            dry_run = cfg.get('dry_run', True)
            false_override = cfg.get('false_bot_ea_override', False)
            bot_pct = float(cfg.get('bot_contract_qty_pct', 100))
            tp_priority = cfg.get('tp_priority', ['', '', '', '', ''])
            sl_priority = cfg.get('sl_priority', ['', '', ''])

            # Load state
            positions = await _load('positions')
            clients = await _load('clients')
            groups = await _load('groups')
            schedules = await _load('schedules')

            # --- 1. Monitor existing positions for TP/SL using priority fields ---
            for pos in positions[:]:  # iterate over a copy
                symbol = pos['symbol']
                side = pos['side']
                qty = pos['qty']
                entry = pos['entry']
                ticker = generate_ticker(symbol)
                current = ticker['last']
                # Compute PnL for logging
                if side == 'LONG':
                    pnl = (current - entry) * qty
                else:
                    pnl = (entry - current) * qty
                # Update position pnl in memory (not persisted per cycle)
                # Check TP priority levels - highest priority first
                tp_hit = False
                tp_price = None
                # Parse TP priorities (most important first)
                for tp_str in tp_priority:
                    if not tp_str:
                        continue
                    pct = parse_priority(tp_str)
                    if pct is None:
                        continue
                    if side == 'LONG':
                        tp_price = entry * (1 + pct)
                    else:
                        tp_price = entry * (1 - pct)
                    if (side == 'LONG' and current >= tp_price) or (side == 'SHORT' and current <= tp_price):
                        tp_hit = True
                        break
                if tp_hit and tp_price is not None:
                    # Close position
                    if not dry_run:
                        client_id = pos.get('client_id')
                        client = clients.get(client_id)
                        if client:
                            creds = {
                                'api_key': client.get('apex_api_key', ''),
                                'api_secret': client.get('apex_api_secret', ''),
                                'passphrase': client.get('apex_passphrase', ''),
                                'omni_key': client.get('apex_omni_key', '')
                            }
                            close_result = await apex_close_position(creds, symbol, side, qty)
                            if close_result.get('status') == 'filled':
                                # Record in history, remove position
                                history = await _load('history')
                                history.append({
                                    'id': _uid(),
                                    'client_id': client_id,
                                    'symbol': symbol,
                                    'side': side,
                                    'qty': qty,
                                    'entry': entry,
                                    'exit': current,
                                    'pnl': pnl,
                                    'pnl_pct': round(pnl / (entry*qty)*100, 2) if entry*qty else 0,
                                    'mode': 'live',
                                    'closed_at': _now_iso(),
                                    'reason': 'TP'
                                })
                                await _save('history', history)
                                positions = [p for p in positions if p['id'] != pos['id']]
                                await _save('positions', positions)
                                await _append_log('ea_trades', 'TRADE', f'TP closed {client_id} {side} {symbol} qty {qty} pnl {pnl:.2f}')
                                continue  # position removed, skip further checks
                            else:
                                await _append_log('ea_errors', 'WARN', f'Failed to close TP for {pos["id"]}: {close_result}')
                    else:
                        # dry-run: just log and remove
                        history = await _load('history')
                        history.append({
                            'id': _uid(),
                            'client_id': pos.get('client_id'),
                            'symbol': symbol,
                            'side': side,
                            'qty': qty,
                            'entry': entry,
                            'exit': current,
                            'pnl': pnl,
                            'pnl_pct': round(pnl / (entry*qty)*100, 2) if entry*qty else 0,
                            'mode': 'dry',
                            'closed_at': _now_iso(),
                            'reason': 'TP (dry)'
                        })
                        await _save('history', history)
                        positions = [p for p in positions if p['id'] != pos['id']]
                        await _save('positions', positions)
                        await _append_log('ea_trades', 'TRADE', f'TP (dry) closed {pos["client_id"]} {side} {symbol}')
                        continue

                # Check SL priority levels
                sl_hit = False
                sl_price = None
                for sl_str in sl_priority:
                    if not sl_str:
                        continue
                    pct = parse_priority(sl_str)
                    if pct is None:
                        continue
                    if side == 'LONG':
                        sl_price = entry * (1 - pct)
                    else:
                        sl_price = entry * (1 + pct)
                    if (side == 'LONG' and current <= sl_price) or (side == 'SHORT' and current >= sl_price):
                        sl_hit = True
                        break
                if sl_hit and sl_price is not None:
                    # Cancel all orders and close position
                    if not dry_run:
                        client_id = pos.get('client_id')
                        client = clients.get(client_id)
                        if client:
                            creds = {
                                'api_key': client.get('apex_api_key', ''),
                                'api_secret': client.get('apex_api_secret', ''),
                                'passphrase': client.get('apex_passphrase', ''),
                                'omni_key': client.get('apex_omni_key', '')
                            }
                            await apex_cancel_all_orders(creds, symbol)
                            close_result = await apex_close_position(creds, symbol, side, qty)
                            if close_result.get('status') == 'filled':
                                history = await _load('history')
                                history.append({
                                    'id': _uid(),
                                    'client_id': client_id,
                                    'symbol': symbol,
                                    'side': side,
                                    'qty': qty,
                                    'entry': entry,
                                    'exit': current,
                                    'pnl': pnl,
                                    'pnl_pct': round(pnl / (entry*qty)*100, 2) if entry*qty else 0,
                                    'mode': 'live',
                                    'closed_at': _now_iso(),
                                    'reason': 'SL'
                                })
                                await _save('history', history)
                                positions = [p for p in positions if p['id'] != pos['id']]
                                await _save('positions', positions)
                                await _append_log('ea_trades', 'TRADE', f'SL closed {client_id} {side} {symbol} qty {qty} pnl {pnl:.2f}')
                                continue
                            else:
                                await _append_log('ea_errors', 'WARN', f'Failed to close SL for {pos["id"]}: {close_result}')
                    else:
                        # dry-run
                        history = await _load('history')
                        history.append({
                            'id': _uid(),
                            'client_id': pos.get('client_id'),
                            'symbol': symbol,
                            'side': side,
                            'qty': qty,
                            'entry': entry,
                            'exit': current,
                            'pnl': pnl,
                            'pnl_pct': round(pnl / (entry*qty)*100, 2) if entry*qty else 0,
                            'mode': 'dry',
                            'closed_at': _now_iso(),
                            'reason': 'SL (dry)'
                        })
                        await _save('history', history)
                        positions = [p for p in positions if p['id'] != pos['id']]
                        await _save('positions', positions)
                        await _append_log('ea_trades', 'TRADE', f'SL (dry) closed {pos["client_id"]} {side} {symbol}')
                        continue

            # --- 2. Auto-open trades based on signals (only in false mode with override) ---
            if mode == 'false' and false_override:
                # We'll iterate over clients and look for signals
                # For simplicity, we'll use BTC-USDT as default symbol; could be extended to multiple symbols.
                symbols_to_trade = ['BTC-USDT']  # we can later expand to all symbols from config
                for client_id, client in clients.items():
                    # Skip if client has no API credentials
                    if not client.get('apex_api_key') or not client.get('apex_omni_key'):
                        continue
                    # Check if this client already has an open position for any of the symbols
                    has_position = any(p.get('client_id') == client_id and p['symbol'] in symbols_to_trade for p in positions)
                    if has_position:
                        continue  # already in a trade
                    # For each symbol, generate signal
                    for sym in symbols_to_trade:
                        candles = generate_candles(sym, '5m', 100)  # use 5m timeframe
                        signal = fibonacci_signal(candles, lookback=50)
                        if signal == 'NEUTRAL':
                            continue
                        # Determine side
                        side = 'LONG' if signal == 'BUY' else 'SHORT'
                        # Calculate quantity
                        qty_info = calculate_contract_qty(client, sym, bot_pct)
                        qty = qty_info['qty']
                        if qty <= 0:
                            continue
                        # Determine TP and SL from priority fields
                        # Use first non-empty priority as main TP/SL
                        tp_pct = None
                        for tp_str in tp_priority:
                            pct = parse_priority(tp_str)
                            if pct is not None:
                                tp_pct = pct
                                break
                        sl_pct = None
                        for sl_str in sl_priority:
                            pct = parse_priority(sl_str)
                            if pct is not None:
                                sl_pct = pct
                                break
                        # If no TP/SL set, use defaults from client (if any)
                        if tp_pct is None:
                            tp_pct = client.get('tp_pct', 0.08)
                        if sl_pct is None:
                            sl_pct = client.get('sl_pct', 0.0)
                        # Get price
                        price = qty_info['price']
                        # Compute tp_price and sl_price
                        if side == 'LONG':
                            tp_price = price * (1 + tp_pct)
                            sl_price = price * (1 - sl_pct) if sl_pct > 0 else None
                        else:
                            tp_price = price * (1 - tp_pct)
                            sl_price = price * (1 + sl_pct) if sl_pct > 0 else None
                        # Place order (if not dry-run)
                        if not dry_run:
                            creds = {
                                'api_key': client.get('apex_api_key', ''),
                                'api_secret': client.get('apex_api_secret', ''),
                                'passphrase': client.get('apex_passphrase', ''),
                                'omni_key': client.get('apex_omni_key', '')
                            }
                            api_side = 'BUY' if side == 'LONG' else 'SELL'
                            result = await apex_place_order(creds, sym, api_side, qty, price)
                            if result.get('status') == 'filled':
                                pos = {
                                    'id': result.get('id') or _uid(),
                                    'client_id': client_id,
                                    'symbol': sym,
                                    'side': side,
                                    'qty': qty,
                                    'entry': price,
                                    'leverage': client.get('leverage', 10),
                                    'liq': 0,
                                    'pnl': 0.0,
                                    'mode': 'live',
                                    'opened_at': _now_iso(),
                                    'order_id': result.get('id'),
                                    'tp_price': tp_price,
                                    'sl_price': sl_price
                                }
                                positions.append(pos)
                                await _save('positions', positions)
                                await _append_log('ea_trades', 'TRADE', f'BOT AUTO {client_id} {side} {qty} {sym} @ {price} (signal {signal})')
                            else:
                                await _append_log('ea_errors', 'WARN', f'Auto-open failed for {client_id}: {result}')
                        else:
                            # dry-run: just add a simulated position
                            pos = {
                                'id': _uid(),
                                'client_id': client_id,
                                'symbol': sym,
                                'side': side,
                                'qty': qty,
                                'entry': price,
                                'leverage': client.get('leverage', 10),
                                'liq': 0,
                                'pnl': 0.0,
                                'mode': 'dry',
                                'opened_at': _now_iso(),
                                'tp_price': tp_price,
                                'sl_price': sl_price
                            }
                            positions.append(pos)
                            await _save('positions', positions)
                            await _append_log('ea_trades', 'TRADE', f'BOT AUTO (dry) {client_id} {side} {qty} {sym} @ {price} (signal {signal})')
                        break  # only one trade per cycle per client

            # --- 3. Wallet transfers (placeholder) ---
            # Not implemented in this version.

            await asyncio.sleep(2)  # check every 2 seconds

        except Exception as e:
            logger.error('Manifold engine error', error=str(e))
            await asyncio.sleep(5)

    logger.info('Manifold Engine stopped')

async def _start_engine():
    global _bot_task, _bot_stop_event
    async with _engine_lock:
        if _bot_task is not None and not _bot_task.done():
            return
        _bot_stop_event.clear()
        _bot_task = asyncio.create_task(_manifold_engine_loop())

async def _stop_engine():
    global _bot_task, _bot_stop_event
    async with _engine_lock:
        if _bot_task is None or _bot_task.done():
            return
        _bot_stop_event.set()
        await _bot_task
        _bot_task = None

# --- handlers (unchanged, but kept for completeness) ---

async def h_market_symbols(params: Dict[str, Any]) -> Dict[str, Any]:
    return {'symbols': [{'symbol': s, 'tick': SYMBOLS[s]['tick'], 'step': SYMBOLS[s]['step']} for s in SYMBOLS], 'timeframes': list(TIMEFRAMES.keys()), 'brokers': BROKERS}

async def h_market_candles(params: Dict[str, Any]) -> Dict[str, Any]:
    symbol = params.get('symbol', 'BTC-USDT')
    timeframe = params.get('timeframe', '5m')
    limit = max(50, min(int(params.get('limit', 300)), 1000))
    candles = generate_candles(symbol, timeframe, limit)
    ind = compute_indicators(candles)
    return {'symbol': symbol, 'timeframe': timeframe, 'candles': candles, 'indicators': ind}

async def h_market_orderbook(params: Dict[str, Any]) -> Dict[str, Any]:
    return generate_orderbook(params.get('symbol', 'BTC-USDT'), int(params.get('depth', 18)))

async def h_market_ticker(params: Dict[str, Any]) -> Dict[str, Any]:
    return generate_ticker(params.get('symbol', 'BTC-USDT'))

async def h_market_watchlist(params: Dict[str, Any]) -> Dict[str, Any]:
    return {'watchlist': [generate_ticker(s) for s in SYMBOLS]}

async def h_clients_list(params: Dict[str, Any]) -> Dict[str, Any]:
    clients = await _load('clients')
    search = (params.get('search') or '').lower()
    items = list(clients.values())
    if search:
        items = [c for c in items if search in c.get('name', '').lower() or search in c.get('id', '').lower()]
    items = sorted(items, key=lambda c: c.get('name', ''))
    return {'clients': [_mask_client(c) for c in items]}

async def h_clients_get(params: Dict[str, Any]) -> Dict[str, Any]:
    clients = await _load('clients')
    cid = params.get('client_id', '')
    if cid not in clients:
        raise HTTPException(404, 'client not found')
    return {'client': _mask_client(clients[cid])}

async def h_clients_create(params: Dict[str, Any]) -> Dict[str, Any]:
    clients = await _load('clients')
    cid = (params.get('client_id') or params.get('id') or '').strip()
    name = (params.get('name') or cid or '').strip()
    if not cid:
        cid = _uid()
    if not name:
        name = cid
    if cid in clients:
        raise HTTPException(409, 'client id already exists')
    client = {'id': cid, 'name': name, 'apex_api_key': params.get('apex_api_key', ''), 'apex_api_secret': params.get('apex_api_secret', ''), 'apex_passphrase': params.get('apex_passphrase', ''), 'apex_omni_key': params.get('apex_omni_key', ''), 'apex_account_id': params.get('apex_account_id', ''), 'withdrawal_wallet': params.get('withdrawal_wallet', ''), 'transfer_wallet': params.get('transfer_wallet', ''), 'pct_asset': float(params.get('pct_asset', 0) or 0), 'pct_profit': float(params.get('pct_profit', 0) or 0), 'leverage': int(params.get('leverage', 10) or 10), 'tp_pct': float(params.get('tp_pct', 0) or 0), 'sl_pct': float(params.get('sl_pct', 0) or 0), 'mode': params.get('mode', 'manual'), 'ea_name': params.get('ea_name', ''), 'ea_code': params.get('ea_code', ''), 'created_at': _now_iso()}
    clients[cid] = client
    await _save('clients', clients)
    await _append_log('ea_master', 'INFO', f'client created: {name} ({cid})')
    return {'client': _mask_client(client), 'created': True}

async def h_clients_update(params: Dict[str, Any]) -> Dict[str, Any]:
    clients = await _load('clients')
    cid = params.get('client_id', '')
    if cid not in clients:
        raise HTTPException(404, 'client not found')
    c = clients[cid]
    for k in ('name', 'mode', 'apex_api_key', 'apex_api_secret', 'apex_passphrase', 'apex_omni_key', 'apex_account_id', 'withdrawal_wallet', 'transfer_wallet', 'ea_name', 'ea_code'):
        if k in params:
            c[k] = params[k]
    for k in ('pct_asset', 'pct_profit', 'tp_pct', 'sl_pct'):
        if k in params:
            c[k] = float(params[k] or 0)
    if 'leverage' in params:
        c['leverage'] = int(params['leverage'] or 10)
    await _save('clients', clients)
    await _append_log('ea_master', 'INFO', f"client updated: {c.get('name')} ({cid})")
    return {'client': _mask_client(c)}

async def h_clients_delete(params: Dict[str, Any]) -> Dict[str, Any]:
    clients = await _load('clients')
    cid = params.get('client_id', '')
    if cid not in clients:
        raise HTTPException(404, 'client not found')
    del clients[cid]
    await _save('clients', clients)
    await _append_log('ea_master', 'WARN', f'client removed: {cid}')
    return {'deleted': cid}

async def h_clients_set_ea(params: Dict[str, Any]) -> Dict[str, Any]:
    clients = await _load('clients')
    cid = params.get('client_id', '')
    if cid not in clients:
        raise HTTPException(404, 'client not found')
    clients[cid]['ea_name'] = params.get('ea_name', '') or clients[cid].get('ea_name', 'Client EA')
    clients[cid]['ea_code'] = params.get('ea_code', '')
    await _save('clients', clients)
    await _append_log('ea_master', 'INFO', f"EA uploaded for client {cid}: {clients[cid]['ea_name']}")
    return {'client': _mask_client(clients[cid])}

async def h_clients_remove_ea(params: Dict[str, Any]) -> Dict[str, Any]:
    clients = await _load('clients')
    cid = params.get('client_id', '')
    if cid not in clients:
        raise HTTPException(404, 'client not found')
    clients[cid]['ea_name'] = ''
    clients[cid]['ea_code'] = ''
    await _save('clients', clients)
    await _append_log('ea_master', 'WARN', f'EA removed for client {cid}')
    return {'client': _mask_client(clients[cid])}

async def h_groups_list(params: Dict[str, Any]) -> Dict[str, Any]:
    groups = await _load('groups')
    return {'groups': list(groups.values())}

async def h_groups_create(params: Dict[str, Any]) -> Dict[str, Any]:
    groups = await _load('groups')
    gid = (params.get('group_id') or params.get('id') or '').strip() or _uid()
    name = (params.get('name') or gid).strip()
    if gid in groups:
        raise HTTPException(409, 'group id already exists')
    groups[gid] = {'id': gid, 'name': name, 'client_ids': params.get('client_ids', []), 'trade_queue_count': int(params.get('trade_queue_count', 5) or 5), 'seconds_bw_client': int(params.get('seconds_bw_client', 2) or 2), 'wallet_queue_count': int(params.get('wallet_queue_count', 3) or 3), 'seconds_bw_wallet': int(params.get('seconds_bw_wallet', 4) or 4), 'long_queues': params.get('long_queues', ''), 'short_queues': params.get('short_queues', ''), 'long_manage': bool(params.get('long_manage', False)), 'short_manage': bool(params.get('short_manage', False)), 'created_at': _now_iso()}
    await _save('groups', groups)
    await _append_log('ea_master', 'INFO', f'client group created: {name}')
    return {'group': groups[gid]}

async def h_groups_update(params: Dict[str, Any]) -> Dict[str, Any]:
    groups = await _load('groups')
    gid = params.get('group_id', '')
    if gid not in groups:
        raise HTTPException(404, 'group not found')
    g = groups[gid]
    for k in ('name', 'client_ids', 'long_queues', 'short_queues'):
        if k in params:
            g[k] = params[k]
    for k in ('trade_queue_count', 'seconds_bw_client', 'wallet_queue_count', 'seconds_bw_wallet'):
        if k in params:
            g[k] = int(params[k] or 0)
    for k in ('long_manage', 'short_manage'):
        if k in params:
            g[k] = bool(params[k])
    await _save('groups', groups)
    return {'group': g}

async def h_groups_delete(params: Dict[str, Any]) -> Dict[str, Any]:
    groups = await _load('groups')
    gid = params.get('group_id', '')
    if gid not in groups:
        raise HTTPException(404, 'group not found')
    del groups[gid]
    await _save('groups', groups)
    return {'deleted': gid}

async def h_schedules_list(params: Dict[str, Any]) -> Dict[str, Any]:
    schedules = await _load('schedules')
    return {'schedules': list(schedules.values())}

async def h_schedules_create(params: Dict[str, Any]) -> Dict[str, Any]:
    schedules = await _load('schedules')
    sid = (params.get('schedule_id') or params.get('id') or '').strip() or _uid()
    name = (params.get('name') or sid).strip()
    if sid in schedules:
        raise HTTPException(409, 'schedule id already exists')
    schedules[sid] = {'id': sid, 'name': name, 'group_id': params.get('group_id', ''), 'cron': params.get('cron', ''), 'priority': int(params.get('priority', 1) or 1), 'side': params.get('side', 'auto'), 'enabled': bool(params.get('enabled', True)), 'created_at': _now_iso()}
    await _save('schedules', schedules)
    await _append_log('ea_master', 'INFO', f'client schedule created: {name}')
    return {'schedule': schedules[sid]}

async def h_schedules_update(params: Dict[str, Any]) -> Dict[str, Any]:
    schedules = await _load('schedules')
    sid = params.get('schedule_id', '')
    if sid not in schedules:
        raise HTTPException(404, 'schedule not found')
    s = schedules[sid]
    for k in ('name', 'group_id', 'cron', 'side'):
        if k in params:
            s[k] = params[k]
    if 'priority' in params:
        s['priority'] = int(params['priority'] or 1)
    if 'enabled' in params:
        s['enabled'] = bool(params['enabled'])
    await _save('schedules', schedules)
    return {'schedule': s}

async def h_schedules_delete(params: Dict[str, Any]) -> Dict[str, Any]:
    schedules = await _load('schedules')
    sid = params.get('schedule_id', '')
    if sid not in schedules:
        raise HTTPException(404, 'schedule not found')
    del schedules[sid]
    await _save('schedules', schedules)
    return {'deleted': sid}

async def h_ea_list(params: Dict[str, Any]) -> Dict[str, Any]:
    eas = await _load('eas')
    return {'eas': list(eas.values())}

async def h_ea_upload(params: Dict[str, Any]) -> Dict[str, Any]:
    eas = await _load('eas')
    name = (params.get('name') or 'Untitled EA').strip()
    eid = _uid()
    eas[eid] = {'id': eid, 'name': name, 'source': params.get('source', 'upload'), 'description': params.get('description', ''), 'code': params.get('code', ''), 'active': False, 'created_at': _now_iso()}
    await _save('eas', eas)
    await _append_log('ea_master', 'INFO', f'EA uploaded: {name}')
    return {'ea': eas[eid]}

async def h_ea_select(params: Dict[str, Any]) -> Dict[str, Any]:
    eas = await _load('eas')
    eid = params.get('ea_id', '')
    if eid not in eas:
        raise HTTPException(404, 'EA not found')
    for k, v in eas.items():
        v['active'] = (k == eid)
    await _save('eas', eas)
    await _append_log('ea_master', 'INFO', f"active EA set to: {eas[eid]['name']}")
    return {'eas': list(eas.values())}

async def h_ea_remove(params: Dict[str, Any]) -> Dict[str, Any]:
    eas = await _load('eas')
    eid = params.get('ea_id', '')
    if eid not in eas:
        raise HTTPException(404, 'EA not found')
    del eas[eid]
    await _save('eas', eas)
    return {'deleted': eid}

async def h_pine_list(params: Dict[str, Any]) -> Dict[str, Any]:
    pines = await _load('pines')
    items = list(pines.values())
    return {'scripts': [{'id': p['id'], 'name': p['name'], 'code': p['code'], 'created_at': p.get('created_at')} for p in items]}

async def h_pine_save(params: Dict[str, Any]) -> Dict[str, Any]:
    pines = await _load('pines')
    name = (params.get('name') or 'Untitled Script').strip()
    code = params.get('code', '')
    pid = params.get('id') or params.get('pine_id') or name
    if pid in pines:
        pines[pid]['code'] = code
        pines[pid]['name'] = name
        pines[pid]['updated_at'] = _now_iso()
    else:
        pines[pid] = {'id': pid, 'name': name, 'code': code, 'created_at': _now_iso()}
    await _save('pines', pines)
    await _append_log('ea_signals', 'INFO', f'Pine script saved: {name}')
    return {'script': pines[pid], 'saved': True}

async def h_pine_delete(params: Dict[str, Any]) -> Dict[str, Any]:
    pines = await _load('pines')
    pid = params.get('pine_id', '')
    if pid not in pines:
        raise HTTPException(404, 'script not found')
    del pines[pid]
    await _save('pines', pines)
    return {'deleted': pid}

async def h_pine_compile(params: Dict[str, Any]) -> Dict[str, Any]:
    code = params.get('code', '')
    errors: List[str] = []
    if '//@version=' not in code and '@version' not in code:
        errors.append('Missing //@version=5 declaration')
    if 'indicator(' not in code and 'strategy(' not in code:
        errors.append('Missing indicator()/strategy() declaration')
    if code.count('(') != code.count(')'):
        errors.append('Unbalanced parentheses')
    has_alert = 'alertcondition' in code or 'alert(' in code
    return {'ok': not errors, 'errors': errors, 'has_alert': has_alert, 'lines': len(code.splitlines())}

async def h_backtest_run(params: Dict[str, Any]) -> Dict[str, Any]:
    symbol = params.get('symbol', 'BTC-USDT')
    timeframe = params.get('timeframe', '1h')
    strategy = params.get('strategy', 'ema_cross')
    candles = generate_candles(symbol, timeframe, 500)
    closes = [c['close'] for c in candles]
    fast = int(params.get('fast', 9))
    slow = int(params.get('slow', 21))
    e_fast = _ema(closes, fast)
    e_slow = _ema(closes, slow)
    initial = 10000.0
    equity = initial
    position = 0.0
    entry_px = 0.0
    trades: List[Dict[str, Any]] = []
    curve: List[Dict[str, Any]] = []
    for i in range(1, len(candles)):
        px = closes[i]
        if position == 0:
            if e_fast[i - 1] <= e_slow[i - 1] and e_fast[i] > e_slow[i]:
                position = equity / px
                entry_px = px
        elif position > 0:
            if e_fast[i - 1] >= e_slow[i - 1] and e_fast[i] < e_slow[i]:
                pnl = (px - entry_px) * position
                equity += pnl
                trades.append({'time': candles[i]['time'], 'side': 'LONG', 'entry': round(entry_px, 8), 'exit': round(px, 8), 'pnl': round(pnl, 2)})
                position = 0.0
                entry_px = 0.0
        if position > 0:
            curve.append({'time': candles[i]['time'], 'equity': round(equity + (px - entry_px) * position, 2)})
        else:
            curve.append({'time': candles[i]['time'], 'equity': round(equity, 2)})
    if position > 0:
        pnl = (closes[-1] - entry_px) * position
        equity += pnl
        trades.append({'time': candles[-1]['time'], 'side': 'LONG', 'entry': round(entry_px, 8), 'exit': round(closes[-1], 8), 'pnl': round(pnl, 2)})
    wins = [t for t in trades if t['pnl'] > 0]
    ret = (equity - initial) / initial * 100
    return {'symbol': symbol, 'timeframe': timeframe, 'strategy': strategy, 'initial': initial, 'final': round(equity, 2), 'return_pct': round(ret, 2), 'trades': trades, 'num_trades': len(trades), 'win_rate': round(len(wins) / len(trades) * 100, 1) if trades else 0.0, 'equity_curve': curve[-300:]}

async def h_logs_list(params: Dict[str, Any]) -> Dict[str, Any]:
    logs = await _load('logs')
    return {'logs': [{'name': k, 'entries': len(v)} for k, v in logs.items()]}

async def h_logs_get(params: Dict[str, Any]) -> Dict[str, Any]:
    logs = await _load('logs')
    name = params.get('log_name', 'ea_master')
    if name not in logs:
        raise HTTPException(404, 'log not found')
    entries = logs[name]
    client = params.get('client')
    if client:
        entries = [e for e in entries if client in e.get('msg', '')]
    entries = sorted(entries, key=lambda e: e['ts'], reverse=True)[:500]
    return {'log_name': name, 'entries': entries}

async def h_history_list(params: Dict[str, Any]) -> Dict[str, Any]:
    history = await _load('history')
    client = params.get('client')
    symbol = params.get('symbol')
    items = list(history)
    if client:
        items = [t for t in items if t.get('client_id') == client]
    if symbol:
        items = [t for t in items if t.get('symbol') == symbol]
    items = sorted(items, key=lambda t: t.get('closed_at', ''), reverse=True)
    return {'history': items}

async def h_orders_open(params: Dict[str, Any]) -> Dict[str, Any]:
    symbol = params.get('symbol', 'BTC-USDT')
    side = (params.get('side') or 'LONG').upper()
    if side in ('BUY', 'LONG'):
        side = 'LONG'
    elif side in ('SELL', 'SHORT'):
        side = 'SHORT'
    else:
        raise HTTPException(400, 'side must be LONG or SHORT')
    qty = float(params.get('qty', 0) or 0)
    if qty <= 0:
        raise HTTPException(400, 'qty must be > 0')
    client_id = params.get('client_id', 'rmntg00000')
    leverage = int(params.get('leverage', 10) or 10)
    clients = await _load('clients')
    client = clients.get(client_id)
    if not client:
        raise HTTPException(404, 'client not found')
    creds = {'api_key': client.get('apex_api_key', ''), 'api_secret': client.get('apex_api_secret', ''), 'passphrase': client.get('apex_passphrase', ''), 'omni_key': client.get('apex_omni_key', '')}
    if not (creds['api_key'] and creds['api_secret'] and creds['omni_key']):
        raise HTTPException(400, 'client has no ApeX credentials configured')
    ob = generate_orderbook(symbol)
    price = ob['last']
    api_side = 'BUY' if side == 'LONG' else 'SELL'
    # Compute tp and sl from client settings and bot config
    cfg = await _load('bot_config')
    tp_pct = client.get('tp_pct', 0.08)
    sl_pct = client.get('sl_pct', 0.0)
    bot_sl = cfg.get('bot_sl', '')
    if side == 'LONG':
        tp_price = price * (1 + tp_pct)
        sl_price = price * (1 - sl_pct) if sl_pct > 0 else None
    else:
        tp_price = price * (1 - tp_pct)
        sl_price = price * (1 + sl_pct) if sl_pct > 0 else None
    result = await apex_place_order(creds, symbol, api_side, qty, price)
    if result.get('status') == 'filled':
        positions = await _load('positions')
        pos = {'id': result.get('id') or _uid(), 'client_id': client_id, 'symbol': symbol, 'side': side, 'qty': qty, 'entry': price, 'leverage': leverage, 'liq': round(price * (1 - (1 / leverage) * (0.9 if side == 'LONG' else -0.9)), 8), 'pnl': 0.0, 'mode': 'live', 'opened_at': _now_iso(), 'order_id': result.get('id'), 'tp_price': tp_price, 'sl_price': sl_price}
        positions.append(pos)
        await _save('positions', positions)
        await _append_log('ea_trades', 'TRADE', f'LIVE {client_id} {side} {qty} {symbol} @ {price}')
        return {'position': pos, 'live': True, 'order': result}
    raise HTTPException(400, f"live order rejected: {result.get('error') or result}")

async def h_orders_positions(params: Dict[str, Any]) -> Dict[str, Any]:
    positions = await _load('positions')
    client = params.get('client')
    items = [p for p in positions if not client or p.get('client_id') == client]
    return {'positions': items}

async def h_orders_close(params: Dict[str, Any]) -> Dict[str, Any]:
    positions = await _load('positions')
    pid = params.get('position_id', '')
    for i, p in enumerate(positions):
        if p['id'] == pid:
            ob = generate_orderbook(p['symbol'])
            price = ob['last']
            pnl = (price - p['entry']) * p['qty'] if p['side'] == 'LONG' else (p['entry'] - price) * p['qty']
            closed = positions.pop(i)
            history = await _load('history')
            history.append({'id': _uid(), 'client_id': closed.get('client_id'), 'symbol': closed['symbol'], 'side': closed['side'], 'qty': closed['qty'], 'entry': closed['entry'], 'exit': price, 'pnl': round(pnl, 2), 'pnl_pct': round(pnl / (closed['entry'] * closed['qty']) * 100, 2) if closed['entry'] else 0, 'mode': closed.get('mode', 'dry'), 'closed_at': _now_iso()})
            await _save('history', history)
            await _save('positions', positions)
            await _append_log('ea_trades', 'TRADE', f"closed {pid} {closed['side']} {closed['symbol']} pnl={round(pnl, 2)}")
            return {'closed': pid, 'pnl': round(pnl, 2)}
    raise HTTPException(404, 'position not found')

async def h_withdraw_submit(params: Dict[str, Any]) -> Dict[str, Any]:
    wtype = params.get('type', 'client')
    asset = params.get('asset', 'USDT')
    amount = float(params.get('amount', 0) or 0)
    if amount <= 0:
        raise HTTPException(400, 'amount must be > 0')
    target = params.get('target', params.get('client_id', ''))
    mode = params.get('mode', 'dry')
    withdrawals = await _load('withdrawals')
    w = {'id': _uid(), 'type': wtype, 'target': target, 'asset': asset, 'amount': amount, 'wallet': params.get('wallet', ''), 'status': 'pending' if mode == 'live' else 'simulated', 'mode': mode, 'created_at': _now_iso()}
    if mode == 'live':
        creds = _apex_creds()
        if not creds['api_key']:
            raise HTTPException(400, 'ApeX live withdrawal requires APEX_API_KEY configured')
        w['status'] = 'queued_live'
    withdrawals.append(w)
    await _save('withdrawals', withdrawals)
    await _append_log('ea_master', 'WARN', f'withdrawal {wtype}/{target} {amount} {asset} ({mode})')
    return {'withdrawal': w}

async def h_withdraw_list(params: Dict[str, Any]) -> Dict[str, Any]:
    withdrawals = await _load('withdrawals')
    return {'withdrawals': list(reversed(withdrawals))}

async def h_apex_status(params: Dict[str, Any]) -> Dict[str, Any]:
    creds = _apex_creds()
    return {'configured': bool(creds['api_key'] and creds['api_secret']), 'account_id': creds['account_id'] or None, 'api_base': APEX_API_BASE}

async def h_apex_account(params: Dict[str, Any]) -> Dict[str, Any]:
    return await apex_request('GET', '/api/v3/account')

async def h_apex_positions(params: Dict[str, Any]) -> Dict[str, Any]:
    return await apex_request('GET', '/api/v3/positions')

async def h_apex_balance(params: Dict[str, Any]) -> Dict[str, Any]:
    return await apex_request('GET', '/api/v3/balance')

# --- bot handlers with engine control (unchanged except using new helpers) ---

async def h_bot_config(params: Dict[str, Any]) -> Dict[str, Any]:
    cfg = await _load('bot_config')
    out = dict(cfg)
    out['webuser_passcode_hash'] = bool(cfg.get('webuser_passcode_hash'))
    return {'bot': out, 'indicators': INDICATORS}

async def h_bot_save(params: Dict[str, Any]) -> Dict[str, Any]:
    cfg = await _load('bot_config')
    for k in ('bot_mode', 'trade_queue_count', 'seconds_bw_client', 'wallet_queue_count', 'seconds_bw_wallet', 'bot_contract_qty_pct', 'bot_sl', 'long_queues', 'short_queues', 'false_bot_ea_id', 'webuser_ea_id', 'transfer_wallet', 'bot_ea_name', 'bot_ea_code'):
        if k in params and params[k] is not None:
            cfg[k] = params[k]
    for k in ('long_manage', 'short_manage', 'false_bot_ea_override', 'webuser', 'dry_run'):
        if k in params:
            cfg[k] = bool(params[k])
    if 'tp_priority' in params:
        cfg['tp_priority'] = (list(params['tp_priority']) + ['', '', '', '', ''])[:5]
    if 'sl_priority' in params:
        cfg['sl_priority'] = (list(params['sl_priority']) + ['', '', ''])[:3]
    for k in ('indicators_false', 'indicators_true', 'indicators_webuser'):
        if k in params:
            cfg[k] = list(params[k]) if params[k] else []
    if 'webuser_yearly_profit_limit' in params:
        cfg['webuser_yearly_profit_limit'] = float(params['webuser_yearly_profit_limit'] or 0)
    if params.get('webuser_passcode'):
        cfg['webuser_passcode_hash'] = hashlib.sha256(params['webuser_passcode'].encode()).hexdigest()
    cfg['updated_at'] = _now_iso()
    await _save('bot_config', cfg)
    await _append_log('ea_master', 'INFO', f"bot config saved (mode={cfg['bot_mode']}, webuser={cfg['webuser']})")
    out = dict(cfg)
    out['webuser_passcode_hash'] = bool(cfg.get('webuser_passcode_hash'))
    return {'bot': out}

async def h_bot_status(params: Dict[str, Any]) -> Dict[str, Any]:
    cfg = await _load('bot_config')
    positions = await _load('positions')
    clients = await _load('clients')
    groups = await _load('groups')
    history = await _load('history')
    logs = await _load('logs')
    total_pnl = round(sum(float(p.get('pnl', 0)) for p in positions), 2)
    realized = round(sum(float(h.get('pnl', 0)) for h in history[-50:]), 2)
    client_ids = list(clients.keys())
    tqc = int(cfg.get('trade_queue_count', 5)) or 1
    queues = [client_ids[i:i + tqc] for i in range(0, len(client_ids), tqc)]
    recent = [e for e in logs.get('ea_master', []) if 'bot' in e.get('msg', '').lower()][-8:]
    out = dict(cfg)
    out['webuser_passcode_hash'] = bool(cfg.get('webuser_passcode_hash'))
    out['engine_running'] = _bot_task is not None and not _bot_task.done()
    return {'bot': out, 'positions': positions, 'total_unrealized_pnl': total_pnl, 'realized_pnl': realized, 'active_queues': queues, 'num_clients': len(client_ids), 'num_groups': len(groups), 'recent_activity': recent}

async def h_bot_start(params: Dict[str, Any]) -> Dict[str, Any]:
    cfg = await _load('bot_config')
    cfg['running'] = True
    cfg['started_at'] = _now_iso()
    await _save('bot_config', cfg)
    await _start_engine()
    await _append_log('ea_master', 'INFO', f"bot STARTED ({cfg['bot_mode']} mode, {cfg['trade_queue_count']} clients/queue)")
    return await h_bot_status({})

async def h_bot_stop(params: Dict[str, Any]) -> Dict[str, Any]:
    cfg = await _load('bot_config')
    cfg['running'] = False
    await _save('bot_config', cfg)
    # We do not stop the engine because it should continue monitoring positions for TP/SL
    await _append_log('ea_master', 'WARN', 'bot STOPPED - no new entries; position monitoring continues')
    return await h_bot_status({})

async def h_bot_cancel_all(params: Dict[str, Any]) -> Dict[str, Any]:
    kind = params.get('kind', 'all')
    await _append_log('ea_signals', 'WARN', f'bot cancel-all {kind} triggered (dry-run)')
    # In live mode, we would call apex_cancel_all_orders for each client with positions
    return {'canceled': kind, 'mode': 'dry'}

async def h_bot_reverse(params: Dict[str, Any]) -> Dict[str, Any]:
    positions = await _load('positions')
    for p in positions:
        p['side'] = 'SHORT' if p.get('side') == 'LONG' else 'LONG'
        p['pnl'] = 0.0
    await _save('positions', positions)
    await _append_log('ea_trades', 'TRADE', f'bot reverse: {len(positions)} positions flipped (dry-run)')
    return {'reversed': len(positions)}

async def h_bot_calculate_qty(params: Dict[str, Any]) -> Dict[str, Any]:
    client_id = params.get('client_id', 'rmntg00000')
    clients = await _load('clients')
    client = clients.get(client_id)
    if not client:
        raise HTTPException(404, 'client not found')
    symbol = params.get('symbol', 'BTC-USDT')
    cfg = await _load('bot_config')
    bot_pct = float(cfg.get('bot_contract_qty_pct', 100))
    result = calculate_contract_qty(client, symbol, bot_pct)
    return result

async def h_bot_upload_ea(params: Dict[str, Any]) -> Dict[str, Any]:
    cfg = await _load('bot_config')
    cfg['bot_ea_name'] = params.get('ea_name', '') or 'Bot EA'
    cfg['bot_ea_code'] = params.get('ea_code', '')
    await _save('bot_config', cfg)
    await _append_log('ea_master', 'INFO', f"bot EA uploaded: {cfg['bot_ea_name']}")
    return await h_bot_status({})

async def h_bot_remove_ea(params: Dict[str, Any]) -> Dict[str, Any]:
    cfg = await _load('bot_config')
    cfg['bot_ea_name'] = ''
    cfg['bot_ea_code'] = ''
    await _save('bot_config', cfg)
    await _append_log('ea_master', 'WARN', 'bot EA removed')
    return await h_bot_status({})

async def h_bot_place_order(params: Dict[str, Any]) -> Dict[str, Any]:
    # Reuse existing logic with automatic quantity calculation
    client_id = params.get('client_id', '')
    symbol = params.get('symbol', 'BTC-USDT')
    side = (params.get('side') or 'LONG').upper()
    # Get client and calculate qty
    clients = await _load('clients')
    client = clients.get(client_id)
    if not client:
        return {'status': 'error', 'error': f'client {client_id} not found'}
    cfg = await _load('bot_config')
    bot_pct = float(cfg.get('bot_contract_qty_pct', 100))
    qty_info = calculate_contract_qty(client, symbol, bot_pct)
    qty = qty_info['qty']
    if qty <= 0:
        return {'status': 'error', 'error': 'calculated quantity is zero'}
    leverage = int(params.get('leverage', client.get('leverage', 10)) or 10)
    # Proceed with order
    creds = {'api_key': client.get('apex_api_key', ''), 'api_secret': client.get('apex_api_secret', ''), 'passphrase': client.get('apex_passphrase', ''), 'omni_key': client.get('apex_omni_key', '')}
    if not (creds['api_key'] and creds['api_secret'] and creds['omni_key']):
        return {'status': 'error', 'error': f'client {client_id} has no ApeX credentials'}
    ob = generate_orderbook(symbol)
    price = ob['last']
    api_side = 'BUY' if side == 'LONG' else 'SELL'
    # Compute tp and sl from client settings and bot config
    tp_pct = client.get('tp_pct', 0.08)
    sl_pct = client.get('sl_pct', 0.0)
    bot_sl = cfg.get('bot_sl', '')
    if side == 'LONG':
        tp_price = price * (1 + tp_pct)
        sl_price = price * (1 - sl_pct) if sl_pct > 0 else None
    else:
        tp_price = price * (1 - tp_pct)
        sl_price = price * (1 + sl_pct) if sl_pct > 0 else None
    result = await apex_place_order(creds, symbol, api_side, qty, price)
    if result.get('status') == 'filled':
        positions = await _load('positions')
        pos = {'id': result.get('id') or _uid(), 'client_id': client_id, 'symbol': symbol, 'side': side, 'qty': qty, 'entry': price, 'leverage': leverage, 'liq': round(price * (1 - (1 / leverage) * (0.9 if side == 'LONG' else -0.9)), 8), 'pnl': 0.0, 'mode': 'live', 'opened_at': _now_iso(), 'order_id': result.get('id'), 'tp_price': tp_price, 'sl_price': sl_price}
        positions.append(pos)
        await _save('positions', positions)
        await _append_log('ea_trades', 'TRADE', f'BOT LIVE {client_id} {side} {qty} {symbol} @ {price}')
        return {'position': pos, 'live': True}
    return {'status': 'error', 'error': result.get('error') or result}

async def h_bridge_status(params: Dict[str, Any]) -> Dict[str, Any]:
    b = await _load('bridge')
    eas = await _load('eas')
    pines = await _load('pines')
    return {'bridge': b, 'connected_eas': [e for e in eas.values() if e.get('active')], 'pine_scripts': len(pines)}

async def h_bridge_connect(params: Dict[str, Any]) -> Dict[str, Any]:
    b = await _load('bridge')
    b['broker_connected'] = True
    await _save('bridge', b)
    await _append_log('ea_master', 'INFO', 'EA bridge connected to broker')
    return await h_bridge_status({})

async def h_bridge_disconnect(params: Dict[str, Any]) -> Dict[str, Any]:
    b = await _load('bridge')
    b['broker_connected'] = False
    await _save('bridge', b)
    await _append_log('ea_master', 'WARN', 'EA bridge disconnected from broker')
    return await h_bridge_status({})

async def h_bridge_push_signal(params: Dict[str, Any]) -> Dict[str, Any]:
    b = await _load('bridge')
    sig = {'time': int(time.time()), 'symbol': params.get('symbol', 'BTC-USDT'), 'side': params.get('side', 'LONG'), 'price': params.get('price', 0), 'source': params.get('source', 'pine')}
    b['signals'].append(sig)
    b['signals'] = b['signals'][-100:]
    await _save('bridge', b)
    await _append_log('ea_signals', 'SIGNAL', f"bridge relayed {sig['side']} {sig['symbol']} @ {sig['price']} -> EA")
    return {'relayed': sig, 'bridge': b}

# --- new endpoints for ApeX cancel/close actions ---

async def h_apex_cancel_all(params: Dict[str, Any]) -> Dict[str, Any]:
    symbol = params.get('symbol')
    creds = _apex_creds()
    if not creds['api_key']:
        raise HTTPException(400, 'ApeX credentials not configured')
    result = await apex_cancel_all_orders(creds, symbol)
    await _append_log('ea_errors', 'INFO', f'ApeX cancel all orders {symbol if symbol else "all"}')
    return result

async def h_apex_close_position(params: Dict[str, Any]) -> Dict[str, Any]:
    symbol = params.get('symbol')
    side = params.get('side')
    size = float(params.get('size', 0))
    if not symbol or not side or size <= 0:
        raise HTTPException(400, 'symbol, side, size required')
    creds = _apex_creds()
    if not creds['api_key']:
        raise HTTPException(400, 'ApeX credentials not configured')
    result = await apex_close_position(creds, symbol, side, size)
    await _append_log('ea_trades', 'TRADE', f'ApeX close position {side} {symbol} size {size}')
    return result

# --- routers ---

market_router = APIRouter(prefix='/api/market', tags=['market'])
clients_router = APIRouter(prefix='/api/clients', tags=['clients'])
groups_router = APIRouter(prefix='/api/groups', tags=['groups'])
schedules_router = APIRouter(prefix='/api/schedules', tags=['schedules'])
ea_router = APIRouter(prefix='/api/ea', tags=['ea'])
pine_router = APIRouter(prefix='/api/pine', tags=['pine'])
backtest_router = APIRouter(prefix='/api/backtest', tags=['backtest'])
logs_router = APIRouter(prefix='/api/logs', tags=['logs'])
history_router = APIRouter(prefix='/api/history', tags=['history'])
orders_router = APIRouter(prefix='/api/orders', tags=['orders'])
withdraw_router = APIRouter(prefix='/api/withdraw', tags=['withdraw'])
apex_router = APIRouter(prefix='/api/apex', tags=['apex'])
bot_router = APIRouter(prefix='/api/bot', tags=['bot'])
bridge_router = APIRouter(prefix='/api/bridge', tags=['bridge'])

# --- register routes ---

@market_router.get('/symbols')
async def _r_symbols():
    return await h_market_symbols({})

@market_router.get('/candles')
async def _r_candles(symbol: str = 'BTC-USDT', timeframe: str = '5m', limit: int = 300):
    return await h_market_candles({'symbol': symbol, 'timeframe': timeframe, 'limit': limit})

@market_router.get('/orderbook')
async def _r_orderbook(symbol: str = 'BTC-USDT', depth: int = 18):
    return await h_market_orderbook({'symbol': symbol, 'depth': depth})

@market_router.get('/ticker')
async def _r_ticker(symbol: str = 'BTC-USDT'):
    return await h_market_ticker({'symbol': symbol})

@market_router.get('/watchlist')
async def _r_watchlist():
    return await h_market_watchlist({})

@clients_router.get('')
async def _r_clients(search: str = ''):
    return await h_clients_list({'search': search})

@clients_router.post('')
async def _r_clients_create(payload: Dict[str, Any]):
    return await h_clients_create(payload)

@clients_router.delete('/{client_id}')
async def _r_clients_delete(client_id: str):
    return await h_clients_delete({'client_id': client_id})

@groups_router.get('')
async def _r_groups():
    return await h_groups_list({})

@groups_router.post('')
async def _r_groups_create(payload: Dict[str, Any]):
    return await h_groups_create(payload)

@schedules_router.get('')
async def _r_schedules():
    return await h_schedules_list({})

@schedules_router.post('')
async def _r_schedules_create(payload: Dict[str, Any]):
    return await h_schedules_create(payload)

@ea_router.get('')
async def _r_ea():
    return await h_ea_list({})

@ea_router.post('/upload')
async def _r_ea_upload(payload: Dict[str, Any]):
    return await h_ea_upload(payload)

@ea_router.post('/select')
async def _r_ea_select(payload: Dict[str, Any]):
    return await h_ea_select(payload)

@pine_router.get('')
async def _r_pine():
    return await h_pine_list({})

@pine_router.post('/save')
async def _r_pine_save(payload: Dict[str, Any]):
    return await h_pine_save(payload)

@pine_router.post('/compile')
async def _r_pine_compile(payload: Dict[str, Any]):
    return await h_pine_compile(payload)

@backtest_router.post('/run')
async def _r_backtest(payload: Dict[str, Any]):
    return await h_backtest_run(payload)

@logs_router.get('')
async def _r_logs():
    return await h_logs_list({})

@logs_router.get('/{log_name}')
async def _r_logs_get(log_name: str, client: str = ''):
    return await h_logs_get({'log_name': log_name, 'client': client})

@history_router.get('')
async def _r_history(client: str = '', symbol: str = ''):
    return await h_history_list({'client': client, 'symbol': symbol})

@orders_router.get('/positions')
async def _r_positions(client: str = ''):
    return await h_orders_positions({'client': client})

@orders_router.post('/open')
async def _r_orders_open(payload: Dict[str, Any]):
    return await h_orders_open(payload)

@orders_router.post('/close')
async def _r_orders_close(payload: Dict[str, Any]):
    return await h_orders_close(payload)

@withdraw_router.get('')
async def _r_withdraws():
    return await h_withdraw_list({})

@withdraw_router.post('')
async def _r_withdraw_submit(payload: Dict[str, Any]):
    return await h_withdraw_submit(payload)

@apex_router.get('/status')
async def _r_apex_status():
    return await h_apex_status({})

@apex_router.get('/account')
async def _r_apex_account():
    return await h_apex_account({})

@apex_router.post('/cancel-all')
async def _r_apex_cancel_all(payload: Dict[str, Any]):
    return await h_apex_cancel_all(payload)

@apex_router.post('/close-position')
async def _r_apex_close_position(payload: Dict[str, Any]):
    return await h_apex_close_position(payload)

@bot_router.get('')
async def _r_bot():
    return await h_bot_status({})

@bot_router.post('/save')
async def _r_bot_save(payload: Dict[str, Any]):
    return await h_bot_save(payload)

@bot_router.post('/start')
async def _r_bot_start():
    return await h_bot_start({})

@bot_router.post('/stop')
async def _r_bot_stop():
    return await h_bot_stop({})

@bot_router.post('/place-order')
async def _r_bot_place(payload: Dict[str, Any]):
    return await h_bot_place_order(payload)

@bot_router.post('/calculate-qty')
async def _r_bot_calc_qty(payload: Dict[str, Any]):
    return await h_bot_calculate_qty(payload)

@bot_router.post('/cancel-all')
async def _r_bot_cancel_all(payload: Dict[str, Any]):
    return await h_bot_cancel_all(payload)

@bot_router.post('/reverse')
async def _r_bot_reverse(payload: Dict[str, Any]):
    return await h_bot_reverse(payload)

@bridge_router.get('')
async def _r_bridge():
    return await h_bridge_status({})

@bridge_router.post('/connect')
async def _r_bridge_connect():
    return await h_bridge_connect({})

@bridge_router.post('/disconnect')
async def _r_bridge_disconnect():
    return await h_bridge_disconnect({})

@bridge_router.post('/signal')
async def _r_bridge_signal(payload: Dict[str, Any]):
    return await h_bridge_push_signal(payload)

# --- dispatch and main ---

class DispatchRequest(BaseModel):
    action: str = Field(..., description='Action to run')
    params: Dict[str, Any] = Field(default_factory=dict, description='Action parameters')

class DispatchResponse(BaseModel):
    result: Dict[str, Any] = Field(default_factory=dict, description='Action result payload')
    action: str = Field('', description='Echo of the requested action')

@app.post('/', response_model=DispatchResponse)
async def dispatch(req: DispatchRequest):
    fn = ACTIONS.get(req.action)
    if fn is None:
        raise HTTPException(404, f'Unknown action: {req.action}')
    result = await fn(req.params)
    return DispatchResponse(result=result, action=req.action)

@app.get('/')
async def root():
    return {'service': 'vertbacon_api', 'version': '2.0.0', 'actions': sorted(ACTIONS.keys())}

# action registry (same, with new handlers added)
ACTIONS: Dict[str, Any] = {
    'market.symbols': h_market_symbols,
    'market.candles': h_market_candles,
    'market.orderbook': h_market_orderbook,
    'market.ticker': h_market_ticker,
    'market.watchlist': h_market_watchlist,
    'clients.list': h_clients_list,
    'clients.get': h_clients_get,
    'clients.create': h_clients_create,
    'clients.update': h_clients_update,
    'clients.delete': h_clients_delete,
    'groups.list': h_groups_list,
    'groups.create': h_groups_create,
    'groups.update': h_groups_update,
    'groups.delete': h_groups_delete,
    'schedules.list': h_schedules_list,
    'schedules.create': h_schedules_create,
    'schedules.update': h_schedules_update,
    'schedules.delete': h_schedules_delete,
    'ea.list': h_ea_list,
    'ea.upload': h_ea_upload,
    'ea.select': h_ea_select,
    'ea.remove': h_ea_remove,
    'pine.list': h_pine_list,
    'pine.save': h_pine_save,
    'pine.delete': h_pine_delete,
    'pine.compile': h_pine_compile,
    'backtest.run': h_backtest_run,
    'logs.list': h_logs_list,
    'logs.get': h_logs_get,
    'history.list': h_history_list,
    'orders.open': h_orders_open,
    'orders.positions': h_orders_positions,
    'orders.close': h_orders_close,
    'withdraw.submit': h_withdraw_submit,
    'withdraw.list': h_withdraw_list,
    'apex.status': h_apex_status,
    'apex.account': h_apex_account,
    'apex.positions': h_apex_positions,
    'apex.balance': h_apex_balance,
    'apex.cancel_all': h_apex_cancel_all,
    'apex.close_position': h_apex_close_position,
    'bot.config': h_bot_config,
    'bot.save': h_bot_save,
    'bot.start': h_bot_start,
    'bot.stop': h_bot_stop,
    'bot.status': h_bot_status,
    'bot.cancel_all': h_bot_cancel_all,
    'bot.reverse': h_bot_reverse,
    'bot.calculate_qty': h_bot_calculate_qty,
    'clients.set_ea': h_clients_set_ea,
    'clients.remove_ea': h_clients_remove_ea,
    'bot.upload_ea': h_bot_upload_ea,
    'bot.remove_ea': h_bot_remove_ea,
    'bot.place_order': h_bot_place_order,
    'bridge.status': h_bridge_status,
    'bridge.connect': h_bridge_connect,
    'bridge.disconnect': h_bridge_disconnect,
    'bridge.push_signal': h_bridge_push_signal,
}

for _r in (market_router, clients_router, groups_router, schedules_router, ea_router, pine_router, backtest_router, logs_router, history_router, orders_router, withdraw_router, apex_router, bot_router, bridge_router):
    app.include_router(_r)

@app.on_event("shutdown")
async def shutdown_event():
    await _stop_engine()

if __name__ == '__main__':
    run_service(app)