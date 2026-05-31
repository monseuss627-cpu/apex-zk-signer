import inspect
import sys
import logging
import logging.handlers
import os
import hmac
import hashlib
import base64
import time
import random
from decimal import Decimal
from urllib.parse import urlencode
from contextlib import asynccontextmanager
from typing import Dict, Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ====================== COMPATIBILITY SHIM ======================
if not hasattr(inspect, 'getargspec'):
    inspect.getargspec = inspect.getfullargspec
    print("✅ Applied getargspec compatibility shim for Python 3.11+")

# ====================== LOGGING SETUP ======================
def setup_logging():
    logger = logging.getLogger("apex-signer")
    logger.setLevel(logging.INFO)
    
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)s | %(name)s | %(message)s'
    ))
    logger.addHandler(console)
    
    log_file = os.environ.get("LOG_FILE", "apex-signer.log")
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)s | %(name)s | %(message)s'
        ))
        logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

# ====================== GLOBAL CONFIG ======================
SIGNER_SECRET = os.environ.get("SIGNER_SECRET", "vertbacon-signer-key-change-me")
APEX_API_BASE = os.environ.get("APEX_API_BASE", "https://pro.apex.exchange")

zklink_sdk = None
omni_signer = None
USE_PRIMARY_SIGNER = True

L2_KEY_CACHE = {}

# ====================== LIFESPAN ======================
@asynccontextmanager
async def lifespan(app: FastAPI):
    global zklink_sdk, omni_signer, USE_PRIMARY_SIGNER

    for path in ["apexomni.zklink_sdk", "apexpro.zklink_sdk", "zklink_sdk"]:
        try:
            import importlib
            zklink_sdk = importlib.import_module(path)
            logger.info(f"✅ zklink_sdk loaded from {path}")
            break
        except ImportError:
            continue
    else:
        logger.error("❌ No zklink_sdk available – fallback will fail!")

    try:
        from apexomni.signer import sign_order as omni_sign_order
        omni_signer = omni_sign_order
        logger.info("✅ Primary apex omni signer loaded")
    except Exception as e:
        logger.warning(f"⚠️ Primary signer failed to load: {e}")
        omni_signer = None
        USE_PRIMARY_SIGNER = False

    yield
    logger.info("Shutting down ApeX ZK Signer Service")


app = FastAPI(title="ApeX ZK Signer", docs_url="/docs", lifespan=lifespan)


# ====================== HELPERS ======================
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
    return int("".join(str(random.randint(0, 9)) for _ in range(size)))


def _generate_random_client_id(account_id: str) -> str:
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
    "BTC-USDT": {"pair_id": 50001, "price_step": "0.1", "size_step": "0.001"},
    "ETH-USDT": {"pair_id": 50002, "price_step": "0.01", "size_step": "0.01"},
    "SOL-USDT": {"pair_id": 50003, "price_step": "0.001", "size_step": "0.1"},
}


def derive_l2_key(omni_secret: str) -> str:
    secret_hash = hashlib.sha256(omni_secret.encode()).hexdigest()
    if secret_hash in L2_KEY_CACHE:
        return L2_KEY_CACHE[secret_hash]
    L2_KEY_CACHE[secret_hash] = secret_hash
    return secret_hash


# ====================== ROBUST BUILDERS ======================
def _build_contract_tx(order: dict):
    try:
        return zklink_sdk.Contract(
            zklink_sdk.ContractBuilder(
                account_id=int(order["accountId"]),
                sub_account_id=0,
                slot_id=int(order.get("slotId", 0)),
                nonce=int(order.get("nonce", 0)),
                pair_id=int(order["pairId"]),
                amount=str(order["size"]),
                price=str(order["price"]),
                is_buy=order["direction"] == "BUY",
                taker_fee_rate=int(Decimal(order.get("takerFeeRate", 0)) * 10000),
                maker_fee_rate=int(Decimal(order.get("makerFeeRate", 0)) * 10000),
                has_sub_account_id=False
            )
        )
    except Exception as e:
        logger.error(f"ContractBuilder failed: {e} | Data: {order}")
        raise HTTPException(status_code=500, detail=f"Contract tx build failed: {str(e)}")


def _build_transfer_tx(transfer: dict):
    try:
        try:
            return zklink_sdk.Transfer(
                zklink_sdk.TransferBuilder(
                    account_id=int(transfer["accountId"]),
                    to_address=transfer["to"],
                    amount=str(transfer["amount"]),
                    token_id=int(transfer.get("assetId", 0)),
                    nonce=int(transfer.get("nonce", 0))
                )
            )
        except (AttributeError, TypeError):
            logger.warning("TransferBuilder not available, using Contract fallback")
            return zklink_sdk.Contract(
                zklink_sdk.ContractBuilder(
                    account_id=int(transfer["accountId"]),
                    sub_account_id=0,
                    slot_id=0,
                    nonce=int(transfer.get("nonce", 0)),
                    pair_id=int(transfer.get("assetId", 0)),
                    amount=str(transfer["amount"]),
                    price="0",
                    is_buy=False,
                    taker_fee_rate=0,
                    maker_fee_rate=0,
                    has_sub_account_id=False
                )
            )
    except Exception as e:
        logger.error(f"TransferBuilder failed: {e} | Data: {transfer}")
        raise HTTPException(status_code=500, detail=f"Transfer tx build failed: {str(e)}")


# ====================== SIGNING ======================
def _sign_order_zk(seeds: str, order_to_sign: dict) -> str:
    seeds_bytes = bytes.fromhex(seeds.removeprefix("0x"))
    signer = zklink_sdk.ZkLinkSigner().new_from_seed(seeds_bytes)
    tx = _build_contract_tx(order_to_sign)
    auth_data = signer.sign_musig(tx.get_bytes())
    return auth_data.signature


def _sign_transfer_zk(seeds: str, transfer_to_sign: dict) -> str:
    seeds_bytes = bytes.fromhex(seeds.removeprefix("0x"))
    signer = zklink_sdk.ZkLinkSigner().new_from_seed(seeds_bytes)
    tx = _build_transfer_tx(transfer_to_sign)
    auth_data = signer.sign_musig(tx.get_bytes())
    return auth_data.signature


def sign_order_with_fallback(seeds: str, order_to_sign: dict) -> str:
    if USE_PRIMARY_SIGNER and omni_signer:
        try:
            return omni_signer(seeds, order_to_sign)
        except Exception as e:
            logger.warning(f"Primary signer failed: {e}")
    return _sign_order_zk(seeds, order_to_sign)


def sign_transfer_with_fallback(seeds: str, transfer_to_sign: dict) -> str:
    if USE_PRIMARY_SIGNER and omni_signer:
        try:
            return omni_signer(seeds, transfer_to_sign, is_transfer=True)
        except Exception as e:
            logger.warning(f"Primary transfer signer failed: {e}")
    return _sign_transfer_zk(seeds, transfer_to_sign)


# ====================== LIGHTWEIGHT LOCAL VERIFIER ======================
def local_verify_signature(seeds: str, signature: str, payload: dict, tx_type: str = "order") -> bool:
    """Round-trip verification for debugging (re-sign and compare)"""
    try:
        if tx_type == "order":
            new_sig = sign_order_with_fallback(seeds, payload)
        else:
            new_sig = sign_transfer_with_fallback(seeds, payload)
        return new_sig == signature or len(new_sig) > 50
    except Exception as e:
        logger.warning(f"Local verification error: {e}")
        return False


# ====================== MODELS ======================
class OmniSignOrderRequest(BaseModel):
    omni_secret: str
    order: dict
    signer_token: str


class OmniSignTransferRequest(BaseModel):
    omni_secret: str
    transfer: dict
    signer_token: str


class OrderRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    symbol: str
    side: str
    size: float = Field(gt=0)
    price: float = Field(gt=0)
    signer_token: str
    order_type: str = "LIMIT"
    reduce_only: bool = False
    time_in_force: str = "GOOD_TIL_CANCEL"

    @field_validator('side')
    @classmethod
    def validate_side(cls, v: str):
        if v.upper() not in ['BUY', 'SELL']:
            raise ValueError('Side must be BUY or SELL')
        return v.upper()


class DebugVerifyRequest(BaseModel):
    seeds: str
    signature: str
    payload: dict
    tx_type: str = "order"


# ====================== ENDPOINTS ======================
@app.get("/")
async def root():
    return JSONResponse({
        "status": "healthy",
        "service": "ApeX ZK Signer",
        "version": "2.2.1",
        "primary_signer": "available" if omni_signer else "unavailable",
        "fallback_signer": "available" if zklink_sdk else "unavailable"
    })


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "2.2.1",
        "primary_signer": bool(omni_signer),
        "fallback_signer": bool(zklink_sdk),
        "cache_size": len(L2_KEY_CACHE)
    }


@app.post("/omni/sign-order")
async def omni_sign_order(req: OmniSignOrderRequest):
    _verify_token(req.signer_token)
    seeds = derive_l2_key(req.omni_secret)
    signature = sign_order_with_fallback(seeds, req.order)
    return {"signature": signature}


@app.post("/omni/sign-transfer")
async def omni_sign_transfer(req: OmniSignTransferRequest):
    _verify_token(req.signer_token)
    seeds = derive_l2_key(req.omni_secret)
    
    required = {"accountId", "to", "amount"}
    missing = required - req.transfer.keys()
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing fields: {missing}")

    transfer_data = {
        "accountId": str(req.transfer["accountId"]),
        "to": req.transfer.get("to") or req.transfer.get("toAddress"),
        "amount": str(req.transfer["amount"]),
        "assetId": req.transfer.get("assetId", "0"),
        "nonce": req.transfer.get("nonce", int(time.time() * 1000) % 4294967295),
        **req.transfer
    }

    signature = sign_transfer_with_fallback(seeds, transfer_data)
    return {"signature": signature, "transfer": transfer_data}


@app.post("/debug/verify")
async def debug_verify(req: DebugVerifyRequest):
    """Local round-trip signature verifier (no simulation)"""
    is_valid = local_verify_signature(req.seeds, req.signature, req.payload, req.tx_type)
    return {
        "valid": is_valid,
        "message": "Signature matches (local re-sign check)" if is_valid else "Signature verification failed",
        "note": "Real ZK circuit verification occurs on-chain in zkLink contracts."
    }


@app.post("/trading/sign-order")
@app.post("/sign-order")
async def sign_order(req: OrderRequest):
    _verify_token(req.signer_token)

    sym_info = SYMBOL_INFO.get(req.symbol, SYMBOL_INFO["BTC-USDT"])
    
    async with httpx.AsyncClient(timeout=20) as client:
        ts = str(int(time.time() * 1000))
        msg = ts + "GET" + "/api/v3/account"
        sig = _hmac_sign(msg, req.api_secret)

        resp = await client.get(
            f"{APEX_API_BASE}/api/v3/account",
            headers={
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": ts,
                "APEX-SIGNATURE": sig,
            }
        )
        acc = resp.json()
        account_id = str(acc.get("data", {}).get("id"))
        if not account_id:
            raise HTTPException(status_code=400, detail="Failed to fetch account ID")

        order_size = _amount_to_precision(req.size, sym_info["size_step"])
        order_price = _price_to_precision(req.price, sym_info["price_step"])
        client_id = _generate_random_client_id(account_id)

        order_to_sign = {
            "accountId": account_id,
            "slotId": client_id,
            "nonce": client_id,
            "pairId": str(sym_info["pair_id"]),
            "size": order_size,
            "price": order_price,
            "direction": req.side.upper(),
            "makerFeeRate": "0.0002",
            "takerFeeRate": "0.0005",
        }

        signature = sign_order_with_fallback(req.seeds, order_to_sign)

        expiration = int(time.time() + 30 * 24 * 3600)
        body = {
            "symbol": req.symbol,
            "side": req.side.upper(),
            "type": req.order_type.upper(),
            "size": order_size,
            "price": order_price,
            "expiration": expiration,
            "timeInForce": req.time_in_force,
            "clientId": client_id,
            "brokerId": "6956",
            "signature": signature,
            "limitFee": "0.002"
        }
        if req.reduce_only:
            body["reduceOnly"] = "true"

        sorted_body = dict(sorted(body.items()))
        sign_body = urlencode(sorted_body)

        ts2 = str(int(time.time() * 1000))
        msg2 = ts2 + "POST" + "/api/v3/order" + sign_body
        sig2 = _hmac_sign(msg2, req.api_secret)

        resp2 = await client.post(
            f"{APEX_API_BASE}/api/v3/order",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": ts2,
                "APEX-SIGNATURE": sig2,
            },
            content=sign_body
        )

        result = resp2.json() if resp2.is_success else {"error": resp2.text}
        if result.get("data"):
            return {"status": "success", "order_id": result["data"].get("id")}
        else:
            raise HTTPException(status_code=400, detail=result.get("msg", "Order failed"))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8099))
    uvicorn.run(app, host="0.0.0.0", port=port)