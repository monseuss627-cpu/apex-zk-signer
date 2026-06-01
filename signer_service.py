from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, Dict
import os
import logging
import traceback
import asyncio
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apex-signer")

app = FastAPI(title="ApeX ZK Signer", version="3.4.0", docs_url="/docs")

SIGNER_SECRET = os.environ.get("SIGNER_SECRET", "vertbacon-signer-key-change-me")
APEX_API_BASE = os.environ.get("APEX_API_BASE", "https://omni.apex.exchange")
PORT = int(os.environ.get("PORT", 8099))

active_connections: list[WebSocket] = []

# --------------------------- Imports ---------------------------
HttpPrivateSign = None
_import_errors: Dict[str, str] = {}

def _try_imports():
    global HttpPrivateSign
    try:
        from apexomni.http_private_sign import HttpPrivateSign as _HPS
        HttpPrivateSign = _HPS
        logger.info("✅ Loaded apexomni.http_private_sign.HttpPrivateSign")
    except Exception as e:
        _import_errors["HttpPrivateSign"] = f"{type(e).__name__}: {e}"
        logger.error("Import failed: %s", _import_errors["HttpPrivateSign"])

@app.on_event("startup")
async def startup():
    _try_imports()

# --------------------------- Schemas ---------------------------

class OrderRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    symbol: str                    # e.g. "BTC-USDT"
    side: str                      # BUY / SELL
    size: float
    price: float = 0.0             # REQUIRED even for MARKET
    signer_token: str
    order_type: str = "MARKET"     # MARKET | LIMIT
    reduce_only: bool = False
    time_in_force: str = "GOOD_TIL_CANCEL"
    client_order_id: Optional[str] = None

class TransferRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    amount: str
    asset: str = "USDT"
    signer_token: str

class WithdrawRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    amount: str
    asset: str = "USDT"
    to_chain_id: int
    is_fast_withdraw: bool = False
    signer_token: str

def _verify_token(token: str):
    if token != SIGNER_SECRET:
        raise HTTPException(status_code=403, detail="Invalid signer token")

def _build_client(req):
    if HttpPrivateSign is None:
        raise HTTPException(status_code=500, detail="Signer not loaded")

    client = HttpPrivateSign(
        endpoint=APEX_API_BASE,
        zk_seeds=req.seeds,
        api_key_credentials={
            "key": req.api_key,
            "secret": req.api_secret,
            "passphrase": req.passphrase,
        },
    )
    # Official requirement: preload configs and account
    try:
        client.configs_v3()
        client.get_account_v3()
    except Exception as e:
        logger.warning("Preload failed: %s", e)
    return client

# --------------------------- WebSocket ---------------------------

async def broadcast(message: dict):
    msg = json.dumps({**message, "timestamp": datetime.utcnow().isoformat()})
    for ws in active_connections[:]:
        try:
            await ws.send_text(msg)
        except:
            if ws in active_connections:
                active_connections.remove(ws)

# --------------------------- UI (Standalone HTML) ---------------------------

@app.get("/ui", response_class=HTMLResponse)
async def ui():
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>ApeX Signer Control</title>
        <style>
            body { font-family: monospace; background:#0a0a0a; color:#00ff9d; padding:20px; }
            .section { background:#111; border:1px solid #00ff9d33; padding:20px; margin:15px 0; border-radius:8px; }
            input, select, button { padding:10px; margin:5px; background:#1a1a1a; border:1px solid #00ff9d; color:#00ff9d; }
            button { background:#00aa77; cursor:pointer; font-weight:bold; }
            button:hover { background:#00ff9d; color:black; }
            #log { background:#000; height:420px; overflow-y:scroll; padding:15px; font-size:0.9em; }
            .success { color:#00ff9d; } .error { color:#ff4444; }
        </style>
    </head>
    <body>
    <div style="max-width:1100px;margin:auto">
        <h1>ApeX ZK Signer UI (v3.4)</h1>
        <p><strong>Signer URL:</strong> <input type="text" id="signerUrl" value="https://your-app.onrender.com" style="width:420px;"></p>

        <div class="section">
            <h2>Place Order (Exact ApeX Format)</h2>
            <input type="text" id="apiKey" placeholder="API Key" style="width:280px;">
            <input type="text" id="apiSecret" placeholder="API Secret" style="width:280px;">
            <input type="text" id="passphrase" placeholder="Passphrase">
            <input type="text" id="seeds" placeholder="ZK Seeds">
            <input type="text" id="signerToken" placeholder="Signer Token">

            <br><br>
            Symbol: <input type="text" id="symbol" value="BTC-USDT">
            Side: <select id="side"><option value="BUY">BUY</option><option value="SELL">SELL</option></select>
            Type: <select id="orderType" onchange="togglePrice()">
                <option value="MARKET">MARKET</option>
                <option value="LIMIT">LIMIT</option>
            </select>
            Size: <input type="number" id="size" value="0.001" step="0.0001">
            Price: <input type="number" id="price" value="65000" step="0.1"> <small>(required even for MARKET)</small>
            <button onclick="placeOrder()">Send Order</button>
        </div>

        <div class="section">
            <h2>Transfers</h2>
            Amount: <input type="text" id="transferAmount" value="10">
            Asset: <input type="text" id="transferAsset" value="USDT">
            <button onclick="transferPerpToFunding()">Perp → Funding</button>
            <button onclick="transferFundingToPerp()">Funding → Perp</button>
        </div>

        <div class="section">
            <h2>Withdrawal</h2>
            Amount: <input type="text" id="withdrawAmount" value="10">
            Asset: <input type="text" id="withdrawAsset" value="USDT">
            Chain ID: <input type="number" id="toChainId" value="42161">
            <label><input type="checkbox" id="fastWithdraw" checked> Fast Withdraw</label>
            <button onclick="withdraw()">Withdraw</button>
        </div>

        <div class="section">
            <h2>Live Events</h2>
            <div id="log"></div>
            <button onclick="clearLog()">Clear</button>
        </div>
    </div>

    <script>
    let ws = null;
    function connectWS() {
        const url = document.getElementById('signerUrl').value.replace('http','ws') + '/ws';
        ws = new WebSocket(url);
        ws.onopen = () => log("WebSocket Connected", "success");
        ws.onmessage = e => log(e.data, "success");
        ws.onclose = () => { log("WS Disconnected - Reconnecting...", "error"); setTimeout(connectWS, 3000); };
    }
    connectWS();

    function log(msg, type="info") {
        const div = document.getElementById('log');
        const ts = new Date().toLocaleTimeString();
        div.innerHTML += `<span class="\( {type}">[ \){ts}] ${msg}</span><br>`;
        div.scrollTop = div.scrollHeight;
    }
    function clearLog() { document.getElementById('log').innerHTML = ''; }

    function togglePrice() {
        // Optional UX helper
    }

    async function post(endpoint, payload) {
        try {
            const res = await fetch(document.getElementById('signerUrl').value + endpoint, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            log(`✅ ${endpoint} Success`, "success");
            return data;
        } catch (err) {
            log(`❌ ${endpoint}: ${err.message}`, "error");
        }
    }

    async function placeOrder() {
        const payload = {
            api_key: document.getElementById('apiKey').value,
            api_secret: document.getElementById('apiSecret').value,
            passphrase: document.getElementById('passphrase').value,
            seeds: document.getElementById('seeds').value,
            signer_token: document.getElementById('signerToken').value,
            symbol: document.getElementById('symbol').value,
            side: document.getElementById('side').value,
            size: parseFloat(document.getElementById('size').value),
            price: parseFloat(document.getElementById('price').value),
            order_type: document.getElementById('orderType').value
        };
        await post('/sign-order', payload);
    }

    async function transferPerpToFunding() { await sendTransfer('/sign-transfer-perp-to-funding'); }
    async function transferFundingToPerp() { await sendTransfer('/sign-transfer-funding-to-perp'); }

    async function sendTransfer(endpoint) {
        const payload = {
            api_key: document.getElementById('apiKey').value,
            api_secret: document.getElementById('apiSecret').value,
            passphrase: document.getElementById('passphrase').value,
            seeds: document.getElementById('seeds').value,
            signer_token: document.getElementById('signerToken').value,
            amount: document.getElementById('transferAmount').value,
            asset: document.getElementById('transferAsset').value
        };
        await post(endpoint, payload);
    }

    async function withdraw() {
        const payload = {
            api_key: document.getElementById('apiKey').value,
            api_secret: document.getElementById('apiSecret').value,
            passphrase: document.getElementById('passphrase').value,
            seeds: document.getElementById('seeds').value,
            signer_token: document.getElementById('signerToken').value,
            amount: document.getElementById('withdrawAmount').value,
            asset: document.getElementById('withdrawAsset').value,
            to_chain_id: parseInt(document.getElementById('toChainId').value),
            is_fast_withdraw: document.getElementById('fastWithdraw').checked
        };
        await post('/sign-withdrawal', payload);
    }
    </script>
    </body>
    </html>
    """
    return HTMLResponse(html)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)

# --------------------------- Endpoints ---------------------------

@app.get("/health")
async def health():
    return {"status": "ok" if HttpPrivateSign else "degraded", "version": "3.4.0", "connections": len(active_connections)}

@app.post("/sign-order")
async def sign_order(req: OrderRequest):
    _verify_token(req.signer_token)
    client = _build_client(req)

    try:
        # Exact ApeX requirements
        order_type = req.order_type.upper()
        price_str = str(req.price) if order_type == "LIMIT" or req.price > 0 else "0"

        result = client.create_order_v3(
            symbol=req.symbol,
            side=req.side.upper(),
            type=order_type,
            size=str(req.size),           # MUST be string
            price=price_str,              # MUST be string + required for MARKET
            timeInForce=req.time_in_force,
            reduceOnly=req.reduce_only,
            limitFeeRate="0.0005",        # Adjust to your actual taker fee rate
            clientOrderId=req.client_order_id
        )

        await broadcast({
            "type": "order",
            "status": "success",
            "symbol": req.symbol,
            "side": req.side,
            "size": req.size,
            "price": req.price,
            "order_type": order_type
        })
        return {"status": "success", "raw": result}
    except Exception as e:
        await broadcast({"type": "order", "status": "error", "error": str(e)})
        logger.error(traceback.format_exc())
        return {"error": str(e)}

# Transfer & Withdrawal endpoints remain the same as previous version
@app.post("/sign-transfer-perp-to-funding")
async def transfer_perp_to_funding(req: TransferRequest):
    _verify_token(req.signer_token)
    client = _build_client(req)
    try:
        result = client.create_contract_transfer_out_v3(amount=req.amount, asset=req.asset)
        await broadcast({"type": "transfer", "direction": "perp→funding", "amount": req.amount, "status": "success"})
        return {"status": "success", "result": result}
    except Exception as e:
        return {"error": str(e)}

@app.post("/sign-transfer-funding-to-perp")
async def transfer_funding_to_perp(req: TransferRequest):
    _verify_token(req.signer_token)
    client = _build_client(req)
    try:
        result = client.create_transfer_out_v3(amount=req.amount, asset=req.asset)
        await broadcast({"type": "transfer", "direction": "funding→perp", "amount": req.amount, "status": "success"})
        return {"status": "success", "result": result}
    except Exception as e:
        return {"error": str(e)}

@app.post("/sign-withdrawal")
async def sign_withdrawal(req: WithdrawRequest):
    _verify_token(req.signer_token)
    client = _build_client(req)
    try:
        result = client.create_withdrawal_v3(
            amount=req.amount,
            asset=req.asset,
            toChainId=req.to_chain_id,
            isFastWithdraw=req.is_fast_withdraw
        )
        await broadcast({"type": "withdrawal", "amount": req.amount, "status": "initiated"})
        return {"status": "success", "result": result}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)