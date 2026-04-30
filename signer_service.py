"""
ApeX ZK Order Signing Microservice
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from urllib.parse import urlencode
import hmac
import hashlib
import base64
import time
import httpx
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apex-signer")

app = FastAPI(title="ApeX ZK Signer", docs_url="/docs")

zklink_sdk = None
SIGNER_SECRET = os.environ.get("SIGNER_SECRET", "vertbacon-signer-key-change-me")
APEX_API_BASE = os.environ.get("APEX_API_BASE", "https://pro.apex.exchange")


@app.on_event("startup")
async def load_sdk():
    global zklink_sdk
    try:
        from apexpro import zklink_sdk as sdk
        zklink_sdk = sdk
        logger.info("zklink_sdk loaded successfully")
    except Exception as e:
        logger.error(f"Primary import failed: {e}")
        try:
            import ctypes, glob
            so_files = glob.glob("/usr/local/lib/python3.11/site-packages/apexpro/libzklink_sdk*so*")
            if so_files:
                ctypes.cdll.LoadLibrary(so_files[0])
                from apexpro import zklink_sdk as sdk
                zklink_sdk = sdk
                logger.info("zklink_sdk loaded on retry")
        except Exception as e2:
            logger.error(f"All import attempts failed: {e2}")


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


def _verify_token(token: str):
    if token != SIGNER_SECRET:
        raise HTTPException(status_code=403, detail="Invalid signer token")


def _string_to_base64(s: str) -> str:
    return base64.standard_b64encode(s.encode()).decode()


def _hmac_sign(message: str, secret: str) -> str:
    key = _string_to_base64(secret).encode()
    sig = hmac.new(key, message.encode(), hashlib.sha256).digest()
    return base64.standard_b64encode(sig).decode()


def _sign_order(seeds: str, order_to_sign: dict) -> dict:
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    from decimal import Decimal
    import hashlib as hl

    slot_id_raw = order_to_sign["slotId"]
    nonce_int = int(hl.sha256(slot_id_raw.encode()).hexdigest(), 16)

    max_uint64 = 18446744073709551615
    max_uint32 = 4294967295

    slot_id = int((nonce_int % max_uint64) / max_uint32)
    nonce = nonce_int % max_uint32
    account_id = int(order_to_sign["accountId"]) % max_uint32

    price_str = str(int((Decimal(order_to_sign["price"]) * Decimal(10) ** Decimal('18')).quantize(Decimal(0), rounding='ROUND_DOWN')))
    size_str = str(int((Decimal(order_to_sign["size"]) * Decimal(10) ** Decimal('18')).quantize(Decimal(0), rounding='ROUND_DOWN')))

    taker_fee_rate = int((Decimal(order_to_sign.get("takerFeeRate", "0.0005")) * Decimal(10000)).quantize(Decimal(0), rounding='ROUND_UP'))
    maker_fee_rate = int((Decimal(order_to_sign.get("makerFeeRate", "0.0002")) * Decimal(10000)).quantize(Decimal(0), rounding='ROUND_UP'))

    is_buy = order_to_sign["direction"] == "BUY"

    builder = zklink_sdk.ContractBuilder(
        int(account_id), int(0), int(slot_id), int(nonce),
        int(order_to_sign["pairId"]),
        size_str, price_str, is_buy,
        int(taker_fee_rate), int(maker_fee_rate), False
    )
    tx = zklink_sdk.Contract(builder)
    seeds_bytes = bytes.fromhex(seeds.removeprefix("0x"))
    signer_seed = zklink_sdk.ZkLinkSigner().new_from_seed(seeds_bytes)
    auth_data = signer_seed.sign_musig(tx.get_bytes())
    return {"signature": auth_data.signature}


@app.get("/health")
async def health():
    return {"status": "ok", "zklink_sdk_loaded": zklink_sdk is not None, "version": "1.0.0"}


@app.post("/sign-order")
async def sign_order(req: OrderRequest):
    _verify_token(req.signer_token)
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")

    timestamp = str(int(time.time() * 1000))

    # Step 1: Get account ID
    path_account = "/api/v3/account"
    msg_account = timestamp + "GET" + path_account
    sig_account = _hmac_sign(msg_account, req.api_secret)

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{APEX_API_BASE}{path_account}",
            headers={
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": timestamp,
                "APEX-SIGNATURE": sig_account,
            },
        )
        account_data = resp.json()
        if not account_data.get("data"):
            return {"error": f"Failed to get account: {account_data.get('msg', str(account_data))}"}

        account = account_data["data"]
        account_id = account.get("id") or account.get("accountId")
        if not account_id:
            return {"error": "Could not determine accountId"}

        # Step 2: ZK sign the order
        slot_id = str(int(time.time() * 1000))
        pair_map = {"BTC-USDT": 1, "ETH-USDT": 2, "SOL-USDT": 3}
        pair_id = pair_map.get(req.symbol, 1)

        order_to_sign = {
            "accountId": str(account_id),
            "slotId": slot_id,
            "pairId": str(pair_id),
            "size": str(req.size),
            "price": str(round(req.price, 1)),
            "direction": req.side.upper(),
            "makerFeeRate": "0.0002",
            "takerFeeRate": "0.0005",
        }

        try:
            zk_sig = _sign_order(req.seeds, order_to_sign)
        except Exception as e:
            return {"error": f"ZK signing failed: {str(e)}"}

        # Step 3: Build order params (sorted by key, URL-encoded)
        taker_fee = str(round(req.price * req.size * 0.0005 + 0.01, 6))
        order_body = {
            "clientId": slot_id,
            "isOpenTpslOrder": "false",
            "isSetOpenSl": "false",
            "isSetOpenTp": "false",
            "limitFee": taker_fee,
            "price": str(round(req.price, 1)),
            "reduceOnly": str(req.reduce_only).lower(),
            "side": req.side.upper(),
            "signature": zk_sig["signature"],
            "size": str(req.size),
            "symbol": req.symbol,
            "timeInForce": req.time_in_force,
            "type": "MARKET",
        }

        sorted_body = dict(sorted(order_body.items()))
        sign_body = urlencode(sorted_body)
        path_order = "/api/v3/order"

        # Step 4: HMAC sign the order request (fresh timestamp)
        timestamp2 = str(int(time.time() * 1000))
        msg_order = timestamp2 + "POST" + path_order + sign_body
        sig_order = _hmac_sign(msg_order, req.api_secret)

        # Step 5: Submit as form-encoded POST
        resp = await client.post(
            f"{APEX_API_BASE}{path_order}",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": timestamp2,
                "APEX-SIGNATURE": sig_order,
            },
            content=sign_body,
        )

        try:
            result = resp.json()
        except Exception:
            result = {"raw": resp.text[:500]}

        logger.info(f"ApeX order response: {resp.status_code} - {str(result)[:300]}")

        if result.get("data"):
            order_info = result["data"]
            return {
                "status": "filled",
                "id": order_info.get("id", ""),
                "price": float(order_info.get("price", req.price)),
                "average": float(order_info.get("avgFillPrice") or req.price),
                "filled": float(order_info.get("filledSize") or req.size),
                "symbol": req.symbol,
                "side": req.side,
                "type": "market",
            }
        else:
            return {"error": result.get("msg") or str(result), "code": result.get("code")}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8099))
    uvicorn.run(app, host="0.0.0.0", port=port)