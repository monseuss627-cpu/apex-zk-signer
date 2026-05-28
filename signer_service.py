"""
ApeX ZK Order Signing Microservice
Integrated with omni_secret-based signing (first code) while preserving all paid functionality.
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
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

# ---------- Cache for L2 keys derived from omni_secret (first code) ----------
L2_KEY_CACHE = {}  # {omni_secret_hash: seeds_hex}


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


# ==================== HELPER FUNCTIONS (existing) ====================
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

    price_str = (Decimal(order_to_sign["price"]) * Decimal(10) ** Decimal("18")).quantize(Decimal(0), rounding="ROUND_DOWN")
    size_str = (Decimal(order_to_sign["size"]) * Decimal(10) ** Decimal("18")).quantize(Decimal(0), rounding="ROUND_DOWN")

    taker_fee_rate = (Decimal(order_to_sign["takerFeeRate"]) * Decimal(10000)).quantize(Decimal(0), rounding="ROUND_UP")
    maker_fee_rate = (Decimal(order_to_sign["makerFeeRate"]) * Decimal(10000)).quantize(Decimal(0), rounding="ROUND_UP")

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


# ==================== NEW: omni_secret-based signing (first code integration) ====================
class OmniSignOrderRequest(BaseModel):
    omni_secret: str
    order: dict          # expected to contain: accountId, pairId, size, price, direction, etc.
    signer_token: str    # optional but recommended for security


class OmniSignTransferRequest(BaseModel):
    omni_secret: str
    transfer: dict       # fields for transfer (e.g., to, amount, tokenId)
    signer_token: str


def derive_l2_key(omni_secret: str) -> str:
    """
    Derive an L2 key (seed hex) from an omni_secret.
    Uses SHA256 to get a deterministic 32‑byte seed.
    Production implementation should use a stronger KDF (e.g., PBKDF2) and salt.
    """
    secret_hash = hashlib.sha256(omni_secret.encode()).hexdigest()
    if secret_hash in L2_KEY_CACHE:
        return L2_KEY_CACHE[secret_hash]
    # Simple derivation: treat the SHA256 as the seed hex
    # If omni_secret is a mnemonic, replace this with BIP39 logic.
    seeds_hex = secret_hash
    L2_KEY_CACHE[secret_hash] = seeds_hex
    return seeds_hex


def sign_payload_l2(seeds_hex: str, order_dict: dict) -> str:
    """Sign an order payload using the derived L2 key."""
    # The order_dict must contain the same fields expected by _sign_order_zk
    required_fields = {"accountId", "pairId", "size", "price", "direction", "slotId", "makerFeeRate", "takerFeeRate"}
    missing = required_fields - order_dict.keys()
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing order fields: {missing}")
    return _sign_order_zk(seeds_hex, order_dict)


@app.post("/omni/sign-order")
async def omni_sign_order(req: OmniSignOrderRequest):
    """First code's /sign-order functionality: return signature only using omni_secret."""
    _verify_token(req.signer_token)
    try:
        seeds = derive_l2_key(req.omni_secret)
        signature = sign_payload_l2(seeds, req.order)
        return {"signature": signature}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/omni/sign-transfer")
async def omni_sign_transfer(req: OmniSignTransferRequest):
    """Placeholder for transfer signing (first code integration)."""
    _verify_token(req.signer_token)
    # TODO: implement transfer signing using zklink_sdk if needed
    raise HTTPException(status_code=501, detail="Transfer signing not yet implemented")


# ==================== EXISTING ENDPOINTS (fully preserved) ====================
@app.get("/")
@app.head("/")
async def root():
    return JSONResponse({
        "status": "healthy",
        "service": "ApeX ZK Signer",
        "version": "2.0.8"
    })


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.8"}


@app.get("/trading/diagnose")
@app.post("/trading/diagnose")
async def trading_diagnose():
    return {
        "ok": True,
        "service": "apex-signer",
        "status": "healthy",
        "version": "2.0.8"
    }


@app.post("/trading/start")
async def trading_start():
    if not zklink_sdk:
        raise HTTPException(status_code=500, detail="zklink_sdk not loaded")
    return {
        "ok": True,
        "action": "start",
        "status": "ready",
        "message": "Signer service initialized"
    }


@app.post("/trading/stop")
async def trading_stop():
    return {
        "ok": True,
        "action": "stop",
        "status": "stopped",
        "message": "Signer service stopped"
    }


@app.get("/debug")
@app.post("/debug")
async def debug_info():
    routes = [f"{route.path} [{','.join(sorted(list(route.methods))) if route.methods else 'N/A'}]"
              for route in app.routes if hasattr(route, 'path')]
    return {
        "ok": True,
        "service": "apex-signer",
        "version": "2.0.8",
        "available_routes": routes
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


@app.post("/sign-order")
@app.post("/trading/sign-order")
@app.post("/trading/order")
async def sign_order(req: OrderRequest):
    _verify_token(req.signer_token)

    sym_info = SYMBOL_INFO.get(req.symbol) or SYMBOL_INFO["BTC-USDT"]
    pair_id = sym_info["pair_id"]
    price_step = sym_info["price_step"]
    size_step = sym_info["size_step"]

    timestamp = str(int(time.time() * 1000))
    path_account = "/api/v3/account"
    msg_account = timestamp + "GET" + path_account
    sig_account = _hmac_sign(msg_account, req.api_secret)

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.get(f"{APEX_API_BASE}{path_account}", headers={
            "APEX-API-KEY": req.api_key,
            "APEX-PASSPHRASE": req.passphrase,
            "APEX-TIMESTAMP": timestamp,
            "APEX-SIGNATURE": sig_account,
            "User-Agent": "apex-CCXT",
        })
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

        signature = _sign_order_zk(req.seeds, order_to_sign)

        expiration = int(math.floor(time.time() + 30 * 24 * 60 * 60))

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
            "limitFee": "0.002"
        }

        if req.reduce_only:
            request_body["reduceOnly"] = "true"

        sorted_body = dict(sorted(request_body.items()))
        sign_body = urlencode(sorted_body)

        path_order = "/api/v3/order"
        ts2 = str(int(time.time() * 1000))
        msg_order = ts2 + "POST" + path_order + sign_body
        sig_order = _hmac_sign(msg_order, req.api_secret)

        resp2 = await client.post(f"{APEX_API_BASE}{path_order}", headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "APEX-API-KEY": req.api_key,
            "APEX-PASSPHRASE": req.passphrase,
            "APEX-TIMESTAMP": ts2,
            "APEX-SIGNATURE": sig_order,
        }, content=sign_body)

        try:
            result = resp2.json()
        except:
            result = {"raw": resp2.text[:500]}

        if result.get("data"):
            return {"status": "order_placed", "id": result["data"].get("id")}
        else:
            raise HTTPException(status_code=400, detail=result.get("msg", "Order failed"))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8099))
    uvicorn.run(app, host="0.0.0.0", port=port)