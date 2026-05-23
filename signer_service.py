"""
ApeX ZK Order Signing Microservice
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager
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

zklink_sdk = None
SIGNER_SECRET = os.environ.get("SIGNER_SECRET", "vertbacon-signer-key-change-me")
APEX_API_BASE = os.environ.get("APEX_API_BASE", "https://pro.apex.exchange")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global zklink_sdk
    try:
        from apexomni import zklink_sdk as sdk
        zklink_sdk = sdk
        logger.info("✅ zklink_sdk loaded from apexomni")
    except ImportError:
        try:
            import apexpro.zklink_sdk as sdk
            zklink_sdk = sdk
            logger.info("✅ zklink_sdk loaded from apexpro")
        except ImportError:
            logger.error("❌ Neither apexomni nor apexpro zklink_sdk could be loaded!")
    
    yield
    logger.info("Shutting down ApeX signer service")


app = FastAPI(
    title="ApeX ZK Signer", 
    docs_url="/docs",
    lifespan=lifespan
)


# ==================== ROOT ENDPOINT (Critical for Render Health Checks) ====================
@app.get("/")
@app.head("/")                    # ← This fixes the 405 Method Not Allowed
async def root():
    """Root endpoint supporting both GET and HEAD requests"""
    return JSONResponse({
        "status": "healthy",
        "service": "ApeX ZK Signer",
        "zklink_sdk_loaded": zklink_sdk is not None,
        "version": "2.0.2"
    })


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "zklink_sdk_loaded": zklink_sdk is not None,
        "version": "2.0.2",
        "api_base": APEX_API_BASE,
    }


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
    order_type: str = "LIMIT"
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


SYMBOL_INFO = {
    "BTC-USDT": {"pair_id": 50001, "price_step": "0.1",  "size_step": "0.001"},
    "ETH-USDT": {"pair_id": 50002, "price_step": "0.01", "size_step": "0.01"},
    "SOL-USDT": {"pair_id": 50003, "price_step": "0.001", "size_step": "0.1"},
}


def _sign_order_zk(seeds: str, order_to_sign: dict) -> str:
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    slot_id_raw = order_to_sign["slotId"]
    nonce_int = int(hashlib.sha256(slot_id_raw.encode()).hexdigest(), 16)

    max_uint64 = 18446744073709551615
    max_uint32 = 4294967295

    slot_id = (nonce_int % max_uint64) / max_uint32
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
        int(account_id), 0, int(slot_id), int(nonce),
        int(order_to_sign["pairId"]),
        str(size_str), str(price_str), is_buy,
        int(taker_fee_rate), int(maker_fee_rate), False
    )
    tx = zklink_sdk.Contract(builder)
    seeds_bytes = bytes.fromhex(seeds.removeprefix("0x"))
    signer = zklink_sdk.ZkLinkSigner().new_from_seed(seeds_bytes)
    auth_data = signer.sign_musig(tx.get_bytes())
    return auth_data.signature


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
            raise HTTPException(status_code=400, detail=f"Failed to fetch account: {acc.get('msg')}")

        account_id = str(acc["data"].get("id"))
        if not account_id:
            raise HTTPException(status_code=400, detail="accountId missing")

        order_size = _amount_to_precision(req.size, size_step)
        order_price = _price_to_precision(req.price, price_step)

        client_order_id = _generate_random_client_id_omni(account_id)

        order_to_sign = {
            "accountId": account_id,
            "slotId": client_order_id,
            "nonce": client_order_id,
            "pairId": str(pair_id),
            "size": order_size,
            "price": order_price,
            "direction": req.side.upper(),
            "makerFeeRate": "0.0002",
            "takerFeeRate": "0.0005",
        }

        try:
            signature = _sign_order_zk(req.seeds, order_to_sign)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"ZK signing failed: {str(e)}")

        time_now_ms = int(time.time() * 1000)
        expiration = int(math.floor(time_now_ms / 1000 + 30 * 24 * 60 * 60))

        request_body = {
            "symbol": req.symbol,
            "side": req.side.upper(),
            "type": req.order_type.upper(),
            "size": order_size,
            "price": order_price,
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
            },
            content=sign_body,
        )

        try:
            result = resp2.json()
        except:
            result = {"raw": resp2.text[:500]}

        logger.info(f"ApeX order {req.side} {order_size} {req.symbol} @ {order_price} -> {resp2.status_code}")

        if result.get("data"):
            info = result["data"]
            return {
                "status": "order_placed",
                "id": info.get("id"),
                "client_order_id": client_order_id,
                "raw_response": info
            }
        else:
            raise HTTPException(status_code=400, detail=result.get("msg", "Order failed"))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8099))
    uvicorn.run(app, host="0.0.0.0", port=port)