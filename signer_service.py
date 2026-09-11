"""
ApeX ZK Order Signing Microservice
Deploy on any x86_64 Linux server.
Handles ZK contract signatures for ApeX order submission.
Called via HTTP from the main VertBacon app.

This service mirrors CCXT's `apex.create_order` + `get_zk_contract_signature_obj`
implementations EXACTLY so ApeX accepts the ZK signature.
Extended to support transfers, withdrawals, cancel-all, and enriched PnL records.
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import hmac
import hashlib
import base64
import time
import math
import random
import httpx
import os
import logging
from decimal import Decimal
from urllib.parse import urlencode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apex-signer")

app = FastAPI(title="ApeX ZK Signer", docs_url="/docs")

zklink_sdk = None
SIGNER_SECRET = os.environ.get("SIGNER_SECRET", "vertbacon-signer-key-change-me")
APEX_API_BASE = os.environ.get("APEX_API_BASE", "https://omni.apex.exchange")


@app.on_event("startup")
async def load_sdk():
    global zklink_sdk
    try:
        from apexomni import zklink_sdk as sdk
        zklink_sdk = sdk
        logger.info("zklink_sdk loaded from apexomni")
    except ImportError:
        try:
            import apexpro.zklink_sdk as sdk
            zklink_sdk = sdk
            logger.info("zklink_sdk loaded from apexpro")
        except ImportError:
            logger.error("Neither apexomni nor apexpro zklink_sdk could be loaded!")


# ---------- Request Models ----------
class OrderRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    symbol: str
    side: str
    size: float
    price: float
    signer_token: str
    reduce_only: bool = False
    time_in_force: str = "GOOD_TIL_CANCEL"
    client_id: Optional[str] = None
    client_group_id: Optional[str] = None
    client_schedule_id: Optional[str] = None


class WithdrawRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    amount: str
    asset: str
    to_chain: str
    eth_address: str
    signer_token: str


class TransferRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    asset: str
    amount: str
    from_account: str
    to_account: str
    signer_token: str


class CancelAllRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    signer_token: str
    client_id: Optional[str] = None
    client_group_id: Optional[str] = None
    client_schedule_id: Optional[str] = None


# ---------- PnL Request Models ----------
class EquityRefreshRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    signer_token: str


class EntrySnapshotRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    signer_token: str
    client_id: str
    client_group_id: Optional[str] = None
    client_schedule_id: Optional[str] = None
    symbol: Optional[str] = None
    order_id: Optional[str] = None
    client_order_id: Optional[str] = None
    side: Optional[str] = None
    size: Optional[str] = None
    event_type: str = "ENTRY"          # ENTRY | INCREASE | OPEN


class CancelSnapshotRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    signer_token: str
    client_id: str
    client_group_id: Optional[str] = None
    client_schedule_id: Optional[str] = None
    order_id: Optional[str] = None
    client_order_id: Optional[str] = None
    symbol: Optional[str] = None
    cancel_reason: Optional[str] = None


class PositionDetailsRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    signer_token: str
    client_id: str
    client_group_id: Optional[str] = None
    client_schedule_id: Optional[str] = None
    symbols: Optional[List[str]] = None    # filter, None = all


class OrderHistoryRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    signer_token: str
    client_id: str
    client_group_id: Optional[str] = None
    client_schedule_id: Optional[str] = None
    symbol: Optional[str] = None
    begin_time: Optional[int] = None       # ms epoch
    end_time: Optional[int] = None         # ms epoch
    limit: int = 100
    page: int = 1


class HistoricalPnlRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    signer_token: str
    client_id: str
    client_group_id: Optional[str] = None
    client_schedule_id: Optional[str] = None
    begin_time: Optional[int] = None
    end_time: Optional[int] = None
    limit: int = 100
    page: int = 1


# ---------- In-memory equity cache ----------
# keyed by api_key -> { totalEquityValue, availableBalance, ts }
_EQUITY_CACHE: Dict[str, Dict[str, Any]] = {}


# ---------- Helpers ----------
def _verify_token(token: str):
    if token != SIGNER_SECRET:
        raise HTTPException(status_code=403, detail="Invalid signer token")


def _string_to_base64(s: str) -> str:
    return base64.standard_b64encode(s.encode()).decode()


def _hmac_sign(message: str, secret: str) -> str:
    key = _string_to_base64(secret).encode()
    sig = hmac.new(key, message.encode(), hashlib.sha256).digest()
    return base64.standard_b64encode(sig).decode()


def _rand_number(size: int) -> int:
    return int("".join([str(random.randint(0, 9)) for _ in range(size)]))


def _generate_random_client_id_omni(account_id: str) -> str:
    return f"apexomni-{account_id}-{int(time.time() * 1000)}-{_rand_number(6)}"


def _amount_to_precision(value: float, step: str = "0.001") -> str:
    step_d = Decimal(step)
    v = (Decimal(str(value)) // step_d) * step_d
    return format(v.quantize(step_d), "f")


def _price_to_precision(value: float, step: str = "0.1") -> str:
    step_d = Decimal(step)
    v = (Decimal(str(value)) / step_d).quantize(Decimal(0), rounding="ROUND_HALF_EVEN") * step_d
    return format(v.quantize(step_d), "f")


# Per-symbol precision / l2PairId
SYMBOL_INFO = {
    "BTC-USDT":  {"pair_id": 50001, "price_step": "0.1",  "size_step": "0.001"},
    "ETH-USDT":  {"pair_id": 50002, "price_step": "0.01", "size_step": "0.01"},
    "SOL-USDT":  {"pair_id": 50003, "price_step": "0.001", "size_step": "0.1"},
}


def _sign_order_zk(seeds: str, order_to_sign: dict) -> str:
    """Sign a contract order using zklink_sdk.ContractBuilder."""
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    slot_id_raw = order_to_sign["slotId"]
    nonce_int = int(hashlib.sha256(slot_id_raw.encode()).hexdigest(), 16)

    max_uint64 = 18446744073709551615
    max_uint32 = 4294967295

    # Integer division (fixed)
    slot_id = (nonce_int % max_uint64) // max_uint32
    nonce = nonce_int % max_uint32
    account_id = int(order_to_sign["accountId"]) % max_uint32

    price_str = (Decimal(order_to_sign["price"]) * Decimal(10) ** Decimal("18")).quantize(
        Decimal(0), rounding="ROUND_DOWN")
    size_str = (Decimal(order_to_sign["size"]) * Decimal(10) ** Decimal("18")).quantize(
        Decimal(0), rounding="ROUND_DOWN")

    taker_fee_rate = (Decimal(order_to_sign["takerFeeRate"]) * Decimal(10000)).quantize(
        Decimal(0), rounding="ROUND_UP")
    maker_fee_rate = (Decimal(order_to_sign["makerFeeRate"]) * Decimal(10000)).quantize(
        Decimal(0), rounding="ROUND_UP")

    is_buy = order_to_sign["direction"] == "BUY"

    builder = zklink_sdk.ContractBuilder(
        int(account_id),
        int(0),
        int(slot_id),
        int(nonce),
        int(order_to_sign["pairId"]),
        str(size_str),
        str(price_str),
        is_buy,
        int(taker_fee_rate),
        int(maker_fee_rate),
        False,
    )
    tx = zklink_sdk.Contract(builder)
    seeds_bytes = bytes.fromhex(seeds.removeprefix("0x"))
    signer = zklink_sdk.ZkLinkSigner().new_from_seed(seeds_bytes)
    auth_data = signer.sign_musig(tx.get_bytes())
    return auth_data.signature


def _sign_withdrawal_zk(seeds: str, account_id: str, nonce: int, asset_id: int, amount_scaled: str) -> str:
    """Sign a withdrawal using zklink_sdk.WithdrawBuilder."""
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    builder = zklink_sdk.WithdrawBuilder(
        int(account_id),
        int(nonce),
        int(asset_id),
        str(amount_scaled),
    )
    tx = zklink_sdk.Contract(builder)
    seeds_bytes = bytes.fromhex(seeds.removeprefix("0x"))
    signer = zklink_sdk.ZkLinkSigner().new_from_seed(seeds_bytes)
    auth_data = signer.sign_musig(tx.get_bytes())
    return auth_data.signature


# ---------- PnL Helpers ----------
def _auth_headers(api_key: str, passphrase: str, method: str, path: str,
                  body: str, api_secret: str) -> Dict[str, str]:
    """Build signed ApeX auth headers for any private endpoint."""
    ts = str(int(time.time() * 1000))
    msg = ts + method + path + body
    sig = _hmac_sign(msg, api_secret)
    headers = {
        "APEX-API-KEY": api_key,
        "APEX-PASSPHRASE": passphrase,
        "APEX-TIMESTAMP": ts,
        "APEX-SIGNATURE": sig,
        "User-Agent": "apex-CCXT",
        "Accept": "application/json",
    }
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    return headers


async def _fetch_account_balance(client: httpx.AsyncClient, api_key: str,
                                 api_secret: str, passphrase: str) -> Dict[str, Any]:
    """
    GET /api/v3/account-balance
    Returns authentic broker equity: totalEquityValue, availableBalance,
    initial/maintenance margin, etc.
    """
    path = "/api/v3/account-balance"
    headers = _auth_headers(api_key, passphrase, "GET", path, "", api_secret)
    resp = await client.get(f"{APEX_API_BASE}{path}", headers=headers)
    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text[:500]}
    return {"status_code": resp.status_code, "data": data}


async def _fetch_account(client: httpx.AsyncClient, api_key: str,
                         api_secret: str, passphrase: str) -> Dict[str, Any]:
    """
    GET /api/v3/account
    Returns accountId, contractAccount, contractWallets, positions.
    """
    path = "/api/v3/account"
    headers = _auth_headers(api_key, passphrase, "GET", path, "", api_secret)
    resp = await client.get(f"{APEX_API_BASE}{path}", headers=headers)
    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text[:500]}
    return {"status_code": resp.status_code, "data": data}


def _extract_equity(balance_resp: Dict[str, Any]) -> Dict[str, Any]:
    """Pull equity fields out of /api/v3/account-balance response."""
    body = balance_resp.get("data") or {}
    d = body.get("data") if isinstance(body, dict) else None
    if not isinstance(d, dict):
        d = body if isinstance(body, dict) else {}
    return {
        "totalEquityValue": d.get("totalEquityValue"),
        "availableBalance": d.get("availableBalance"),
        "initialMargin": d.get("initialMargin") or d.get("totalInitialMargin"),
        "maintenanceMargin": d.get("maintenanceMargin") or d.get("totalMaintenanceMargin"),
        "raw": d,
    }


def _normalize_positions(account_resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull positions array out of /api/v3/account response."""
    body = account_resp.get("data") or {}
    d = body.get("data") if isinstance(body, dict) else None
    if not isinstance(d, dict):
        d = body if isinstance(body, dict) else {}
    positions = d.get("positions") or d.get("openPositions") or []
    normalized = []
    for p in positions:
        if not isinstance(p, dict):
            continue
        size = p.get("size")
        try:
            size_f = float(size) if size not in (None, "") else 0.0
        except (TypeError, ValueError):
            size_f = 0.0
        if size_f == 0.0:
            continue
        normalized.append({
            "symbol": p.get("symbol"),
            "side": p.get("side"),
            "size": p.get("size"),
            "entryPrice": p.get("entryPrice"),
            "exitPrice": p.get("exitPrice"),
            "fee": p.get("fee"),
            "fundingFee": p.get("fundingFee"),
            "customInitialMarginRate": p.get("customInitialMarginRate"),
            "createdAt": p.get("createdAt"),
            "updatedTime": p.get("updatedTime") or p.get("updatedAt"),
            "lightNumbers": p.get("lightNumbers"),
        })
    return normalized


def _tag(client_id: str, group_id: Optional[str],
         schedule_id: Optional[str]) -> Dict[str, Any]:
    """Application-level attribution tags echoed back in every record."""
    return {
        "client_id": client_id,
        "client_group_id": group_id,
        "client_schedule_id": schedule_id,
    }


# ---------- Health ----------
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "zklink_sdk_loaded": zklink_sdk is not None,
        "version": "2.2.0",
        "api_base": APEX_API_BASE,
        "equity_cache_entries": len(_EQUITY_CACHE),
    }


# ---------- Sign Order (extended to cache equity + return tags) ----------
@app.post("/sign-order")
async def sign_order(req: OrderRequest):
    _verify_token(req.signer_token)
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    sym_info = SYMBOL_INFO.get(req.symbol) or SYMBOL_INFO["BTC-USDT"]
    pair_id = sym_info["pair_id"]
    price_step = sym_info["price_step"]
    size_step = sym_info["size_step"]

    timestamp = str(int(time.time() * 1000))
    path_account = "/api/v3/account"
    msg_account = timestamp + "GET" + path_account
    sig_account = _hmac_sign(msg_account, req.api_secret)

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            f"{APEX_API_BASE}{path_account}",
            headers={
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": timestamp,
                "APEX-SIGNATURE": sig_account,
                "User-Agent": "apex-CCXT",
                "Accept": "application/json",
            },
        )
        acc = resp.json()
        if not acc.get("data"):
            return {"error": f"Failed to fetch account: {acc.get('msg', str(acc))[:200]}"}

        account_data = acc["data"]
        account_id = account_data.get("id")
        if not account_id:
            return {"error": "accountId missing in /v3/account response"}
        account_id = str(account_id)

        # Opportunistically capture pre-trade equity for downstream PnL attribution
        try:
            pre_balance = await _fetch_account_balance(client, req.api_key,
                                                       req.api_secret, req.passphrase)
            eq = _extract_equity(pre_balance)
            _EQUITY_CACHE[req.api_key] = {
                "totalEquityValue": eq.get("totalEquityValue"),
                "availableBalance": eq.get("availableBalance"),
                "ts": int(time.time() * 1000),
            }
        except Exception as e:
            logger.warning("Pre-trade equity fetch failed: %s", e)

        order_size = _amount_to_precision(req.size, size_step)
        order_price = _price_to_precision(req.price, price_step)

        taker = "0.0005"
        maker = "0.0002"

        fee_val = (Decimal(order_price) * Decimal(order_size) * Decimal(taker)) + Decimal(price_step)
        step_d = Decimal(price_step)
        limit_fee = format(((fee_val // step_d) * step_d).quantize(step_d), "f")

        client_order_id = _generate_random_client_id_omni(account_id)

        order_to_sign = {
            "accountId": account_id,
            "slotId": client_order_id,
            "nonce": client_order_id,
            "pairId": str(pair_id),
            "size": order_size,
            "price": order_price,
            "direction": req.side.upper(),
            "makerFeeRate": maker,
            "takerFeeRate": taker,
        }

        try:
            signature = _sign_order_zk(req.seeds, order_to_sign)
        except Exception as e:
            return {"error": f"ZK signing failed: {str(e)}"}

        time_now_ms = int(time.time() * 1000)
        expiration = int(math.floor(time_now_ms / 1000 + 30 * 24 * 60 * 60))

        request_body = {
            "symbol": req.symbol,
            "side": req.side.upper(),
            "type": "MARKET",
            "size": order_size,
            "price": order_price,
            "limitFee": limit_fee,
            "expiration": expiration,
            "timeInForce": req.time_in_force,
            "clientId": client_order_id,
            "brokerId": "6956",
            "signature": signature,
        }
        if req.reduce_only:
            request_body["reduceOnly"] = "true"

        sorted_body = dict(sorted(request_body.items()))
        sign_body = urlencode(sorted_body)

        path_order = "/api/v3/order"
        ts2 = str(int(time.time() * 1000))
        msg_order = ts2 + "POST" + path_order + sign_body
        sig_order = _hmac_sign(msg_order, req.api_secret)

        resp2 = await client.post(
            f"{APEX_API_BASE}{path_order}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": ts2,
                "APEX-SIGNATURE": sig_order,
                "User-Agent": "apex-CCXT",
                "Accept": "application/json",
            },
            content=sign_body,
        )

        try:
            result = resp2.json()
        except Exception:
            result = {"raw": resp2.text[:500]}

        logger.info(
            "ApeX order %s %s %s @ %s -> %s %s",
            req.side, order_size, req.symbol, order_price, resp2.status_code, str(result)[:300],
        )

        if result.get("data"):
            info = result["data"]
            return {
                "status": "filled",
                "id": info.get("id", ""),
                "price": float(info.get("price") or order_price),
                "average": float(info.get("avgFillPrice") or order_price),
                "filled": float(info.get("filledSize") or order_size),
                "symbol": req.symbol,
                "side": req.side,
                "type": "market",
                "client_order_id": client_order_id,
                "broker": {
                    "createdAt": info.get("createdAt"),
                    "updatedTime": info.get("updatedTime"),
                    "status": info.get("status"),
                    "fee": info.get("fee"),
                    "fundingFee": info.get("fundingFee"),
                },
                "attribution": _tag(req.client_id or "",
                                    req.client_group_id,
                                    req.client_schedule_id),
            }

        return {
            "error": result.get("msg") or str(result)[:300],
            "code": result.get("code"),
            "key": result.get("key"),
            "detail": result.get("detail"),
            "attribution": _tag(req.client_id or "",
                                req.client_group_id,
                                req.client_schedule_id),
        }


# ---------- Transfer ----------
@app.post("/transfer")
async def transfer(req: TransferRequest):
    _verify_token(req.signer_token)

    body = {
        "currency": req.asset,
        "amount": req.amount,
        "from": req.from_account.upper(),
        "to": req.to_account.upper(),
    }
    sorted_body = dict(sorted(body.items()))
    sign_body = urlencode(sorted_body)

    timestamp = str(int(time.time() * 1000))
    path = "/api/v3/transfer"
    msg = timestamp + "POST" + path + sign_body
    sig = _hmac_sign(msg, req.api_secret)

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"{APEX_API_BASE}{path}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": timestamp,
                "APEX-SIGNATURE": sig,
                "User-Agent": "apex-CCXT",
                "Accept": "application/json",
            },
            content=sign_body,
        )
        try:
            result = resp.json()
        except Exception:
            result = {"raw": resp.text[:500]}

        logger.info("Transfer %s %s %s->%s -> %s", req.amount, req.asset, req.from_account, req.to_account, resp.status_code)

        if resp.status_code == 200 and result.get("data"):
            return {"status": "success", "data": result["data"]}
        return {"error": result.get("msg") or str(result)[:300], "code": result.get("code")}


# ---------- Withdrawal ----------
@app.post("/withdraw")
async def withdraw(req: WithdrawRequest):
    _verify_token(req.signer_token)
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    timestamp = str(int(time.time() * 1000))
    path_account = "/api/v3/account"
    msg_account = timestamp + "GET" + path_account
    sig_account = _hmac_sign(msg_account, req.api_secret)

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(
            f"{APEX_API_BASE}{path_account}",
            headers={
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": timestamp,
                "APEX-SIGNATURE": sig_account,
                "User-Agent": "apex-CCXT",
                "Accept": "application/json",
            },
        )
        acc = resp.json()
        if not acc.get("data"):
            return {"error": f"Failed to fetch account: {acc.get('msg', str(acc))[:200]}"}
        account_id = acc["data"].get("id")
        if not account_id:
            return {"error": "accountId missing in /v3/account response"}

        asset_id_map = {"USDT": 0, "BTC": 1, "ETH": 2, "SOL": 3}
        asset_id = asset_id_map.get(req.asset.upper())
        if asset_id is None:
            return {"error": f"Unsupported asset: {req.asset}"}

        amount_scaled = (Decimal(req.amount) * Decimal(10) ** Decimal("18")).quantize(Decimal(0), rounding="ROUND_DOWN")
        amount_str = str(amount_scaled)

        nonce = int(time.time() * 1000) % 4294967295
        try:
            signature = _sign_withdrawal_zk(req.seeds, str(account_id), nonce, asset_id, amount_str)
        except Exception as e:
            return {"error": f"ZK signing failed: {str(e)}"}

        body = {
            "amount": req.amount,
            "currency": req.asset,
            "address": req.eth_address,
            "chain": req.to_chain,
            "signature": signature,
            "nonce": str(nonce),
        }
        sorted_body = dict(sorted(body.items()))
        sign_body = urlencode(sorted_body)

        ts2 = str(int(time.time() * 1000))
        path = "/api/v3/withdraw"
        msg = ts2 + "POST" + path + sign_body
        sig = _hmac_sign(msg, req.api_secret)

        resp2 = await client.post(
            f"{APEX_API_BASE}{path}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": ts2,
                "APEX-SIGNATURE": sig,
                "User-Agent": "apex-CCXT",
                "Accept": "application/json",
            },
            content=sign_body,
        )

        try:
            result = resp2.json()
        except Exception:
            result = {"raw": resp2.text[:500]}

        logger.info("Withdraw %s %s to %s -> %s", req.amount, req.asset, req.eth_address[:8], resp2.status_code)

        if resp2.status_code == 200 and result.get("data"):
            return {"status": "success", "data": result["data"]}
        return {"error": result.get("msg") or str(result)[:300], "code": result.get("code")}


# ---------- Cancel All (Orders + Positions) ----------
@app.post("/cancel-all")
async def cancel_all(req: CancelAllRequest):
    _verify_token(req.signer_token)
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    results = {
        "orders_cancelled": 0,
        "orders_failed": 0,
        "positions_closed": 0,
        "positions_failed": 0,
        "errors": [],
        "attribution": _tag(req.client_id or "",
                            req.client_group_id,
                            req.client_schedule_id),
    }

    async with httpx.AsyncClient(timeout=30) as client:
        def sign_and_headers(method: str, path: str, body: str = ""):
            return _auth_headers(req.api_key, req.passphrase, method, path,
                                 body, req.api_secret)

        # 1) Cancel open orders
        path_orders = "/api/v3/orders?status=OPEN"
        h = sign_and_headers("GET", path_orders)
        resp = await client.get(f"{APEX_API_BASE}{path_orders}", headers=h)
        if resp.status_code != 200:
            results["errors"].append(f"Failed to fetch orders: {resp.text[:200]}")
        else:
            data = resp.json().get("data", [])
            for order in data:
                order_id = order.get("id")
                if not order_id:
                    continue
                path = f"/api/v3/order/{order_id}"
                h = sign_and_headers("DELETE", path)
                resp_del = await client.delete(f"{APEX_API_BASE}{path}", headers=h)
                if resp_del.status_code == 200:
                    results["orders_cancelled"] += 1
                else:
                    results["orders_failed"] += 1
                    results["errors"].append(f"Cancel order {order_id} failed: {resp_del.text[:200]}")

        # 2) Close open positions
        h = sign_and_headers("GET", "/api/v3/account")
        resp_acc = await client.get(f"{APEX_API_BASE}/api/v3/account", headers=h)
        if resp_acc.status_code != 200:
            results["errors"].append(f"Failed to get account: {resp_acc.text[:200]}")
            return results
        account_id = resp_acc.json().get("data", {}).get("id")
        if not account_id:
            results["errors"].append("No account id found")
            return results
        account_id = str(account_id)

        h = sign_and_headers("GET", "/api/v3/positions")
        resp_pos = await client.get(f"{APEX_API_BASE}/api/v3/positions", headers=h)
        if resp_pos.status_code != 200:
            results["errors"].append(f"Failed to fetch positions: {resp_pos.text[:200]}")
            return results
        positions = resp_pos.json().get("data", [])

        for pos in positions:
            size = pos.get("size")
            if not size or size == "0":
                continue
            symbol = pos.get("symbol")
            if not symbol:
                continue
            side = "SELL" if pos["side"].upper() == "LONG" else "BUY"
            sym_info = SYMBOL_INFO.get(symbol) or SYMBOL_INFO["BTC-USDT"]
            size_step = sym_info["size_step"]
            close_size = _amount_to_precision(abs(float(size)), size_step)
            h = sign_and_headers("GET", f"/api/v3/ticker?symbol={symbol}")
            resp_tick = await client.get(f"{APEX_API_BASE}/api/v3/ticker?symbol={symbol}", headers=h)
            if resp_tick.status_code != 200:
                results["errors"].append(f"Could not get ticker for {symbol}, skipping close")
                results["positions_failed"] += 1
                continue
            ticker = resp_tick.json().get("data", {})
            last_price = ticker.get("lastPrice", "0")
            if last_price == "0":
                results["errors"].append(f"Invalid price for {symbol}, skipping")
                results["positions_failed"] += 1
                continue
            price_step = sym_info["price_step"]
            close_price = _price_to_precision(float(last_price), price_step)

            client_order_id = _generate_random_client_id_omni(account_id)
            taker = "0.0005"
            maker = "0.0002"
            order_to_sign = {
                "accountId": account_id,
                "slotId": client_order_id,
                "nonce": client_order_id,
                "pairId": str(sym_info["pair_id"]),
                "size": close_size,
                "price": close_price,
                "direction": side,
                "makerFeeRate": maker,
                "takerFeeRate": taker,
            }
            try:
                signature = _sign_order_zk(req.seeds, order_to_sign)
            except Exception as e:
                results["errors"].append(f"ZK signing for {symbol} close failed: {str(e)}")
                results["positions_failed"] += 1
                continue

            time_now_ms = int(time.time() * 1000)
            expiration = int(math.floor(time_now_ms / 1000 + 30 * 24 * 60 * 60))
            fee_val = (Decimal(close_price) * Decimal(close_size) * Decimal(taker)) + Decimal(price_step)
            step_d = Decimal(price_step)
            limit_fee = format(((fee_val // step_d) * step_d).quantize(step_d), "f")

            body = {
                "symbol": symbol,
                "side": side,
                "type": "MARKET",
                "size": close_size,
                "price": close_price,
                "limitFee": limit_fee,
                "expiration": expiration,
                "timeInForce": "GOOD_TIL_CANCEL",
                "clientId": client_order_id,
                "brokerId": "6956",
                "signature": signature,
                "reduceOnly": "true",
            }
            sorted_body = dict(sorted(body.items()))
            sign_body = urlencode(sorted_body)

            h = sign_and_headers("POST", "/api/v3/order", sign_body)
            resp_order = await client.post(
                f"{APEX_API_BASE}/api/v3/order",
                headers=h,
                content=sign_body,
            )
            if resp_order.status_code == 200:
                results["positions_closed"] += 1
            else:
                results["positions_failed"] += 1
                results["errors"].append(f"Close position {symbol} failed: {resp_order.text[:200]}")

    return results


# ============================================================
# ENRICHED PnL ENDPOINTS
# All data is authentic broker data pulled from ApeX REST APIs.
# The caller's client/group/schedule IDs are echoed back so the
# application can persist them alongside the broker data.
# ============================================================

@app.post("/pnl/refresh-equity")
async def pnl_refresh_equity(req: EquityRefreshRequest):
    """
    Refresh the in-memory equity cache for this API key.
    Calls GET /api/v3/account-balance for authoritative totalEquityValue.
    """
    _verify_token(req.signer_token)
    async with httpx.AsyncClient(timeout=20) as client:
        balance = await _fetch_account_balance(client, req.api_key,
                                               req.api_secret, req.passphrase)
        eq = _extract_equity(balance)
        ts = int(time.time() * 1000)
        _EQUITY_CACHE[req.api_key] = {
            "totalEquityValue": eq.get("totalEquityValue"),
            "availableBalance": eq.get("availableBalance"),
            "ts": ts,
        }
        return {
            "status": "ok",
            "ts": ts,
            "totalEquityValue": eq.get("totalEquityValue"),
            "availableBalance": eq.get("availableBalance"),
            "initialMargin": eq.get("initialMargin"),
            "maintenanceMargin": eq.get("maintenanceMargin"),
            "status_code": balance.get("status_code"),
        }


@app.post("/pnl/entry-snapshot")
async def pnl_entry_snapshot(req: EntrySnapshotRequest):
    """
    Snapshot on entry: broker equity + timestamp + position state.
    Call immediately before submitting an order, or on the first WS
    confirmation that the order is OPEN / filled.
    """
    _verify_token(req.signer_token)

    async with httpx.AsyncClient(timeout=20) as client:
        # Parallel fetch: equity + full account (positions)
        balance_task = _fetch_account_balance(client, req.api_key,
                                              req.api_secret, req.passphrase)
        account_task = _fetch_account(client, req.api_key,
                                      req.api_secret, req.passphrase)
        balance_resp, account_resp = await asyncio_gather(balance_task, account_task)

    eq = _extract_equity(balance_resp)
    positions = _normalize_positions(account_resp)
    if req.symbol:
        positions = [p for p in positions if p.get("symbol") == req.symbol]

    ts = int(time.time() * 1000)
    _EQUITY_CACHE[req.api_key] = {
        "totalEquityValue": eq.get("totalEquityValue"),
        "availableBalance": eq.get("availableBalance"),
        "ts": ts,
    }

    return {
        "event_type": req.event_type,
        "broker": {
            "timestamp_ms": ts,
            "totalEquityValue": eq.get("totalEquityValue"),
            "availableBalance": eq.get("availableBalance"),
            "initialMargin": eq.get("initialMargin"),
            "maintenanceMargin": eq.get("maintenanceMargin"),
        },
        "order": {
            "order_id": req.order_id,
            "client_order_id": req.client_order_id,
            "symbol": req.symbol,
            "side": req.side,
            "size": req.size,
        },
        "positions": positions,
        "attribution": _tag(req.client_id, req.client_group_id,
                            req.client_schedule_id),
        "raw_account_status": account_resp.get("status_code"),
        "raw_balance_status": balance_resp.get("status_code"),
    }


@app.post("/pnl/cancel-snapshot")
async def pnl_cancel_snapshot(req: CancelSnapshotRequest):
    """
    Snapshot on cancel: broker equity + timestamp + residual position state.
    Call when an order reaches CANCELED (WS order update or confirmed cancel).
    """
    _verify_token(req.signer_token)

    async with httpx.AsyncClient(timeout=20) as client:
        balance_task = _fetch_account_balance(client, req.api_key,
                                              req.api_secret, req.passphrase)
        account_task = _fetch_account(client, req.api_key,
                                      req.api_secret, req.passphrase)
        balance_resp, account_resp = await asyncio_gather(balance_task, account_task)

    eq = _extract_equity(balance_resp)
    positions = _normalize_positions(account_resp)
    if req.symbol:
        positions = [p for p in positions if p.get("symbol") == req.symbol]

    ts = int(time.time() * 1000)
    _EQUITY_CACHE[req.api_key] = {
        "totalEquityValue": eq.get("totalEquityValue"),
        "availableBalance": eq.get("availableBalance"),
        "ts": ts,
    }

    return {
        "event_type": "CANCEL",
        "broker": {
            "timestamp_ms": ts,
            "totalEquityValue": eq.get("totalEquityValue"),
            "availableBalance": eq.get("availableBalance"),
            "initialMargin": eq.get("initialMargin"),
            "maintenanceMargin": eq.get("maintenanceMargin"),
        },
        "order": {
            "order_id": req.order_id,
            "client_order_id": req.client_order_id,
            "symbol": req.symbol,
            "cancel_reason": req.cancel_reason,
        },
        "residual_positions": positions,
        "attribution": _tag(req.client_id, req.client_group_id,
                            req.client_schedule_id),
    }


@app.post("/pnl/position-details")
async def pnl_position_details(req: PositionDetailsRequest):
    """
    Return full broker position details: side, size, entryPrice, exitPrice,
    fee, fundingFee, customInitialMarginRate, timestamps, etc.
    """
    _verify_token(req.signer_token)

    async with httpx.AsyncClient(timeout=20) as client:
        account_resp = await _fetch_account(client, req.api_key,
                                            req.api_secret, req.passphrase)

    positions = _normalize_positions(account_resp)
    if req.symbols:
        wanted = set(req.symbols)
        positions = [p for p in positions if p.get("symbol") in wanted]

    return {
        "broker_timestamp_ms": int(time.time() * 1000),
        "positions": positions,
        "attribution": _tag(req.client_id, req.client_group_id,
                            req.client_schedule_id),
    }


@app.post("/pnl/order-history")
async def pnl_order_history(req: OrderHistoryRequest):
    """
    Backfill order lifecycle timestamps and statuses.
    GET /api/v3/order-history with time range + pagination.
    """
    _verify_token(req.signer_token)

    query: Dict[str, Any] = {"limit": req.limit, "page": req.page}
    if req.symbol:
        query["symbol"] = req.symbol
    if req.begin_time:
        query["beginTime"] = req.begin_time
    if req.end_time:
        query["endTime"] = req.end_time
    sorted_query = dict(sorted(query.items()))
    query_str = urlencode(sorted_query)
    path = f"/api/v3/order-history?{query_str}"

    async with httpx.AsyncClient(timeout=20) as client:
        headers = _auth_headers(req.api_key, req.passphrase, "GET", path,
                                "", req.api_secret)
        resp = await client.get(f"{APEX_API_BASE}{path}", headers=headers)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text[:500]}

    orders = data.get("data", []) if isinstance(data, dict) else []
    enriched = []
    for o in orders:
        if not isinstance(o, dict):
            continue
        enriched.append({
            "order_id": o.get("id"),
            "client_order_id": o.get("clientId") or o.get("clientOrderId"),
            "symbol": o.get("symbol"),
            "side": o.get("side"),
            "type": o.get("type"),
            "size": o.get("size"),
            "price": o.get("price"),
            "status": o.get("status"),
            "createdAt": o.get("createdAt"),
            "updatedTime": o.get("updatedTime") or o.get("updatedAt"),
            "expiresAt": o.get("expiresAt") or o.get("expiration"),
            "filledSize": o.get("filledSize"),
            "avgFillPrice": o.get("avgFillPrice"),
            "fee": o.get("fee"),
            "fundingFee": o.get("fundingFee"),
            "reduceOnly": o.get("reduceOnly"),
            "cancelReason": o.get("cancelReason"),
        })

    return {
        "broker_timestamp_ms": int(time.time() * 1000),
        "orders": enriched,
        "pagination": {"limit": req.limit, "page": req.page,
                       "count": len(enriched)},
        "attribution": _tag(req.client_id, req.client_group_id,
                            req.client_schedule_id),
    }


@app.post("/pnl/historical-pnl")
async def pnl_historical_pnl(req: HistoricalPnlRequest):
    """
    Backfill realized/unrealized PnL from ApeX historical PnL endpoint.
    """
    _verify_token(req.signer_token)

    query: Dict[str, Any] = {"limit": req.limit, "page": req.page}
    if req.begin_time:
        query["beginTime"] = req.begin_time
    if req.end_time:
        query["endTime"] = req.end_time
    sorted_query = dict(sorted(query.items()))
    query_str = urlencode(sorted_query)
    path = f"/api/v3/historical-pnl?{query_str}"

    async with httpx.AsyncClient(timeout=20) as client:
        headers = _auth_headers(req.api_key, req.passphrase, "GET", path,
                                "", req.api_secret)
        resp = await client.get(f"{APEX_API_BASE}{path}", headers=headers)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text[:500]}

    records = data.get("data", []) if isinstance(data, dict) else []
    enriched = []
    for r in records:
        if not isinstance(r, dict):
            continue
        enriched.append({
            "symbol": r.get("symbol"),
            "side": r.get("side"),
            "size": r.get("size"),
            "entryPrice": r.get("entryPrice"),
            "exitPrice": r.get("exitPrice"),
            "realizedPnl": r.get("realizedPnl") or r.get("pnl"),
            "fee": r.get("fee"),
            "fundingFee": r.get("fundingFee"),
            "createdAt": r.get("createdAt"),
            "updatedTime": r.get("updatedTime") or r.get("updatedAt"),
            "orderId": r.get("orderId"),
        })

    return {
        "broker_timestamp_ms": int(time.time() * 1000),
        "pnl_records": enriched,
        "pagination": {"limit": req.limit, "page": req.page,
                       "count": len(enriched)},
        "attribution": _tag(req.client_id, req.client_group_id,
                            req.client_schedule_id),
    }


# Small helper so we can run two coroutines concurrently without extra imports
async def asyncio_gather(*coros):
    import asyncio
    return await asyncio.gather(*coros)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8099))
    uvicorn.run(app, host="0.0.0.0", port=port)