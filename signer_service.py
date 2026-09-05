"""
ApeX ZK Order Signing Microservice
Deploy on any x86_64 Linux server.
Handles ZK contract signatures for ApeX order submission.
Called via HTTP from the main VertBacon app.

This service mirrors CCXT's `apex.create_order` + `get_zk_contract_signature_obj`
implementations EXACTLY so ApeX accepts the ZK signature.
Extended to support transfers, withdrawals, and cancel-all.
"""
from fastapi import FastAPI, HTTPException, Response
from fastapi.routing import APIRoute
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
    seeds: str          # needed to sign close orders
    signer_token: str


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


# ---------- Root & Health (with HEAD support) ----------
@app.get("/")
async def root():
    return {
        "service": "ApeX ZK Signer",
        "version": "2.1.0",
        "endpoints": [
            "/health",
            "/sign-order",
            "/transfer",
            "/withdraw",
            "/cancel-all"
        ],
        "docs": "/docs",
        "status": "operational"
    }


@app.head("/")
async def root_head():
    """HEAD request support for health checks."""
    return Response(headers={"Content-Type": "application/json"})


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "zklink_sdk_loaded": zklink_sdk is not None,
        "version": "2.1.0",
        "api_base": APEX_API_BASE,
    }


@app.head("/health")
async def health_head():
    """HEAD request support for health checks."""
    return Response(headers={"Content-Type": "application/json"})


# ---------- Sign Order ----------
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
            }

        return {
            "error": result.get("msg") or str(result)[:300],
            "code": result.get("code"),
            "key": result.get("key"),
            "detail": result.get("detail"),
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

        # Asset ID mapping (extend as needed)
        asset_id_map = {"USDT": 0, "BTC": 1, "ETH": 2, "SOL": 3}
        asset_id = asset_id_map.get(req.asset.upper())
        if asset_id is None:
            return {"error": f"Unsupported asset: {req.asset}"}

        # Scale amount to 18 decimals
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
        "errors": []
    }

    async with httpx.AsyncClient(timeout=30) as client:
        # Helper to sign and get headers
        def sign_and_headers(method: str, path: str, body: str = ""):
            ts = str(int(time.time() * 1000))
            msg = ts + method + path + body
            sig = _hmac_sign(msg, req.api_secret)
            headers = {
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": ts,
                "APEX-SIGNATURE": sig,
                "User-Agent": "apex-CCXT",
                "Accept": "application/json",
            }
            if body:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            return headers

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

        # 2) Close open positions (requires accountId and ZK signing)
        # Fetch accountId
        h = sign_and_headers("GET", "/api/v3/account")
        resp_acc = await client.get(f"{APEX_API_BASE}/api/v3/account", headers=h)
        if resp_acc.status_code != 200:
            results["errors"].append(f"Failed to get account: {resp_acc.text[:200]}")
            # We still return results; positions won't be closed.
            return results
        account_id = resp_acc.json().get("data", {}).get("id")
        if not account_id:
            results["errors"].append("No account id found")
            return results
        account_id = str(account_id)

        # Fetch positions
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
            # Determine opposite side
            side = "SELL" if pos["side"].upper() == "LONG" else "BUY"
            sym_info = SYMBOL_INFO.get(symbol) or SYMBOL_INFO["BTC-USDT"]
            size_step = sym_info["size_step"]
            close_size = _amount_to_precision(abs(float(size)), size_step)
            # Get current price for this symbol
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

            # Build order signature
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

            # Submit close order (market)
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
                "reduceOnly": "true",      # ensure we only close
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


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8099))
    uvicorn.run(app, host="0.0.0.0", port=port)