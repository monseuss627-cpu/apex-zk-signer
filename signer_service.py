"""
ApeX ZK Order Signing Microservice - v3.1.0
Uses apexomni.HttpPrivateSign so the SDK handles all ZK contract
signing internally. No more manual ContractBuilder math.

Endpoints:
  GET  /health        - diagnostic, shows what loaded
  POST /sign-order    - place a signed market/limit order on ApeX Omni
  POST /sign-withdrawal - (stub, not yet implemented)
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import logging
import traceback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apex-signer")

app = FastAPI(title="ApeX ZK Signer", version="3.1.0", docs_url="/docs")

SIGNER_SECRET = os.environ.get("SIGNER_SECRET", "vertbacon-signer-key-change-me")
APEX_API_BASE = os.environ.get("APEX_API_BASE", "https://omni.apex.exchange")

# Module-level imports tested at startup so /health surfaces real errors
HttpPrivateSign = None
zklink_sdk = None
_import_errors: Dict[str, str] = {}


def _try_imports():
    """Import HttpPrivateSign + zklink_sdk and record any failure details."""
    global HttpPrivateSign, zklink_sdk

    # 1) HttpPrivateSign - high-level signed REST client
    try:
        from apexomni.http_private_sign import HttpPrivateSign as _HPS
        HttpPrivateSign = _HPS
        logger.info("Loaded apexomni.http_private_sign.HttpPrivateSign")
    except Exception as e:
        _import_errors["HttpPrivateSign"] = f"{type(e).__name__}: {e}"
        logger.error("HttpPrivateSign import failed: %s", _import_errors["HttpPrivateSign"])

    # 2) zklink_sdk - required for the SDK's internal signing
    try:
        from apexomni import zklink_sdk as _zk
        zklink_sdk = _zk
        logger.info("Loaded apexomni.zklink_sdk")
    except Exception as e:
        try:
            from apexpro import zklink_sdk as _zk2
            zklink_sdk = _zk2
            logger.info("Loaded apexpro.zklink_sdk (fallback)")
        except Exception as e2:
            _import_errors["zklink_sdk"] = f"{type(e).__name__}: {e} || fallback: {type(e2).__name__}: {e2}"
            logger.error("zklink_sdk import failed: %s", _import_errors["zklink_sdk"])

    # 3) Optional deps that the SDK pulls in transitively
    for mod in ("numpy", "mnemonic"):
        try:
            __import__(mod)
        except Exception as e:
            _import_errors[mod] = f"{type(e).__name__}: {e}"
            logger.error("%s import failed: %s", mod, _import_errors[mod])


@app.on_event("startup")
async def startup():
    _try_imports()


# --------------------------- Schemas -----------------------------------

class OrderRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    symbol: str            # "BTC-USDT"
    side: str              # "BUY" / "SELL"
    size: float
    price: float
    signer_token: str
    order_type: str = "MARKET"       # MARKET | LIMIT
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


# --------------------------- Helpers -----------------------------------

def _verify_token(token: str):
    if token != SIGNER_SECRET:
        raise HTTPException(status_code=403, detail="Invalid signer token")


def _build_client(req: OrderRequest):
    """Construct an HttpPrivateSign client. Uses `endpoint=` kwarg per SDK API."""
    if HttpPrivateSign is None:
        raise HTTPException(
            status_code=500,
            detail={"error": "HttpPrivateSign not loaded", "import_errors": _import_errors},
        )

    client = HttpPrivateSign(
        endpoint=APEX_API_BASE,
        zk_seeds=req.seeds,
        api_key_credentials={
            "key": req.api_key,
            "secret": req.api_secret,
            "passphrase": req.passphrase,
        },
    )
    # Load markets / account so SDK knows pairId, decimals, accountId
    try:
        client.configs_v3()
    except Exception as e:
        logger.warning("configs_v3 failed: %s", e)
    try:
        client.get_account_v3()
    except Exception as e:
        logger.warning("get_account_v3 failed: %s", e)
    return client


# --------------------------- Endpoints ---------------------------------

@app.get("/health")
async def health():
    """Detailed diagnostic - no silent failures."""
    return {
        "status": "ok" if (HttpPrivateSign and zklink_sdk) else "degraded",
        "version": "3.1.0",
        "api_base": APEX_API_BASE,
        "loaded": {
            "HttpPrivateSign": HttpPrivateSign is not None,
            "zklink_sdk": zklink_sdk is not None,
        },
        "import_errors": _import_errors or None,
    }


@app.get("/")
async def root():
    return {"service": "apex-zk-signer", "version": "3.1.0", "docs": "/docs"}


@app.post("/sign-order")
async def sign_order(req: OrderRequest):
    """
    Place a signed order on ApeX Omni via the SDK.
    All ZK signing happens inside HttpPrivateSign.create_order_v3.
    """
    _verify_token(req.signer_token)

    if HttpPrivateSign is None or zklink_sdk is None:
        return {
            "error": "Signer not fully loaded",
            "import_errors": _import_errors,
        }

    try:
        client = _build_client(req)
    except HTTPException:
        raise
    except Exception as e:
        return {"error": f"Client init failed: {type(e).__name__}: {e}",
                "traceback": traceback.format_exc()[-800:]}

    try:
        result = client.create_order_v3(
            symbol=req.symbol,
            side=req.side.upper(),
            type=req.order_type.upper(),
            size=str(req.size),
            price=str(req.price),
            timeInForce=req.time_in_force,
            reduceOnly=req.reduce_only,
            limitFeeRate="0.0005",
        )
    except Exception as e:
        return {
            "error": f"create_order_v3 failed: {type(e).__name__}: {e}",
            "traceback": traceback.format_exc()[-800:],
        }

    # SDK returns {"data": {...}} on success
    data = (result or {}).get("data") if isinstance(result, dict) else None
    if data:
        return {
            "status": "filled",
            "id": data.get("id", ""),
            "price": float(data.get("price") or req.price),
            "average": float(data.get("avgFillPrice") or req.price),
            "filled": float(data.get("filledSize") or req.size),
            "symbol": req.symbol,
            "side": req.side,
            "type": req.order_type.lower(),
            "raw": data,
        }

    return {
        "error": (result or {}).get("msg") or str(result)[:400],
        "code": (result or {}).get("code"),
        "raw": result,
    }


@app.post("/sign-withdrawal")
async def sign_withdrawal(req: WithdrawRequest):
    _verify_token(req.signer_token)
    return {"status": "not_implemented_yet", "note": "Use /sign-order for trading"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8099))
    uvicorn.run(app, host="0.0.0.0", port=port)