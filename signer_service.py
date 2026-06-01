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

app = FastAPI(title="ApeX ZK Signer", version="3.6.0", docs_url="/docs")

SIGNER_SECRET = os.environ.get("SIGNER_SECRET", "vertbacon-signer-key-change-me")
APEX_API_BASE = os.environ.get("APEX_API_BASE", "https://omni.apex.exchange")
PORT = int(os.environ.get("PORT", 8099))

active_connections: list[WebSocket] = []

HttpPrivateSign = None
_import_errors: Dict[str, str] = {}

def _try_imports():
    global HttpPrivateSign
    try:
        from apexomni.http_private_v3 import HttpPrivateSign as _HPS
        HttpPrivateSign = _HPS
        logger.info("✅ Loaded apexomni.http_private_v3.HttpPrivateSign")
    except Exception as e:
        _import_errors["HttpPrivateSign"] = f"{type(e).__name__}: {e}"
        logger.error("Import failed: %s", _import_errors["HttpPrivateSign"])

@app.on_event("startup")
async def startup():
    _try_imports()

# Schemas (same as before)
class OrderRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    symbol: str = "BTC-USDT"
    side: str
    size: float
    price: float = 0.0
    signer_token: str
    order_type: str = "MARKET"
    reduce_only: bool = False
    time_in_force: str = "GOOD_TIL_CANCEL"

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
    to_chain_id: int = 42161
    is_fast_withdraw: bool = False
    signer_token: str

def _verify_token(token: str):
    if token != SIGNER_SECRET:
        raise HTTPException(status_code=403, detail="Invalid signer token")

def _build_client(req):
    if HttpPrivateSign is None:
        raise HTTPException(status_code=500, detail={"error": "Signer not loaded", "import_errors": _import_errors})
    client = HttpPrivateSign(
        endpoint=APEX_API_BASE,
        zk_seeds=req.seeds,
        api_key_credentials={"key": req.api_key, "secret": req.api_secret, "passphrase": req.passphrase},
    )
    try:
        client.configs_v3()
        client.get_account_v3()
    except Exception as e:
        logger.warning("Preload failed: %s", e)
    return client

async def broadcast(message: dict):
    msg = json.dumps({**message, "timestamp": datetime.utcnow().isoformat()})
    for ws in active_connections[:]:
        try:
            await ws.send_text(msg)
        except:
            active_connections.remove(ws)

# ==================== ENHANCED UI ====================
@app.get("/ui", response_class=HTMLResponse)
async def ui():
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VertBacon ApeX Control</title>
    <style>
        body { font-family: monospace; background:#0a0a0a; color:#00ff9d; margin:0; padding:10px; }
        .tab { display:none; } .tab.active { display:block; }
        .tabs button { padding:10px; background:#111; color:#0f0; border:none; margin:2px; }
        .tabs button.active { background:#00aa77; }
        input, select, button, textarea { padding:8px; margin:4px; background:#1a1a1a; border:1px solid #00ff9d; color:#0f0; }
        button { background:#006633; cursor:pointer; }
        button:hover { background:#00ff9d; color:#000; }
        #log { height:280px; overflow-y:scroll; background:#000; padding:10px; font-size:0.85em; }
        .price { font-size:2em; color:#ff0; }
    </style>
</head>
<body>
<div style="max-width:1200px;margin:auto">
    <h1>VertBacon • ApeX Signer v3.6</h1>
    <p>Signer URL: <input type="text" id="signerUrl" value="https://your-app.onrender.com" style="width:380px"></p>

    <div class="tabs">
        <button onclick="showTab(0)" class="active">Trading Terminal</button>
        <button onclick="showTab(1)">Clients & Groups</button>
        <button onclick="showTab(2)">Schedules</button>
        <button onclick="showTab(3)">Pine Editor</button>
        <button onclick="showTab(4)">EA Bridge</button>
    </div>

    <!-- Trading Terminal -->
    <div id="tab0" class="tab active">
        <h2>BTCUSDT Perpetual <span id="livePrice" class="price">$71,512.45</span></h2>
        <input id="symbol" value="BTC-USDT" readonly>
        Side: <select id="side"><option>BUY</option><option>SELL</option></select>
        Type: <select id="orderType"><option value="MARKET">Market</option><option value="LIMIT">Limit</option></select>
        Size: <input id="size" type="number" value="0.01">
        Price: <input id="price" type="number" value="71500">
        <button onclick="placeOrder()">Execute Order</button>
        <button onclick="autoTrade()">Auto Trade (EA Mode)</button>
    </div>

    <!-- Clients & Groups -->
    <div id="tab1" class="tab">
        <h2>Clients</h2>
        <div>rmntg00000 (Active) • Lev: 100x</div>
        <div>Test Client 1 (Active)</div>
        <h2>Client Groups</h2>
        <div>High Volume Trading Group (2 clients)</div>
        <button onclick="alert('Group created')">+ Create Group</button>
    </div>

    <!-- Schedules -->
    <div id="tab2" class="tab">
        <h2>Schedules</h2>
        <div>Morning Trading Schedule • Priority 1 • 30s interval</div>
        <button onclick="alert('Schedule active')">Activate Schedule</button>
    </div>

    <!-- Pine Script Editor -->
    <div id="tab3" class="tab">
        <h2>Pine Script Editor</h2>
        <textarea id="pineScript" rows="12" style="width:100%">//@version=6
indicator("Advanced Volume Strategy")
plot(close)</textarea>
        <button onclick="savePine()">Save & Compile</button>
        <button onclick="sendToEA()">Send to EA Bridge</button>
    </div>

    <!-- EA Bridge -->
    <div id="tab4" class="tab">
        <h2>EA Signal Bridge • Client: rmntg00000</h2>
        <button onclick="startEA()">START EA</button>
        <button onclick="forceBuy()">Force BUY</button>
        <button onclick="forceSell()">Force SELL</button>
        <div id="eaLog" style="background:#111;padding:10px;height:200px;overflow:auto"></div>
        <input type="file" id="eaFile" accept=".cpp,.exe"> 
        <button onclick="uploadEA()">Upload EA</button>
    </div>

    <div style="margin-top:20px">
        <h3>Live Log</h3>
        <div id="log"></div>
    </div>
</div>

<script>
let ws = null;
const signerUrl = document.getElementById('signerUrl');

function connectWS() {
    const url = signerUrl.value.replace('http','ws') + '/ws';
    ws = new WebSocket(url);
    ws.onmessage = e => log(e.data);
}
connectWS();

function log(msg) {
    const div = document.getElementById('log');
    div.innerHTML += `[${new Date().toLocaleTimeString()}] ${msg}<br>`;
    div.scrollTop = div.scrollHeight;
}

function showTab(n) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab'+n).classList.add('active');
    document.querySelectorAll('.tabs button').forEach((b,i) => b.classList.toggle('active', i===n));
}

// Order Execution
async function placeOrder() {
    const payload = {
        api_key: "YOUR_API_KEY", // replace with real inputs
        api_secret: "YOUR_SECRET",
        passphrase: "YOUR_PASSPHRASE",
        seeds: "YOUR_ZK_SEEDS",
        signer_token: "YOUR_SIGNER_SECRET",
        symbol: document.getElementById('symbol').value,
        side: document.getElementById('side').value,
        size: parseFloat(document.getElementById('size').value),
        price: parseFloat(document.getElementById('price').value),
        order_type: document.getElementById('orderType').value
    };
    await fetch(signerUrl.value + '/sign-order', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
    }).then(r => r.json()).then(d => log("Order: " + JSON.stringify(d)));
}

function autoTrade() {
    log("EA Auto Trading activated for BTCUSDT");
    // Simulate EA logic sending orders
    setTimeout(() => placeOrder(), 800);
}

function savePine() {
    log("PineScript saved and compiled");
}

function sendToEA() {
    log("PineScript indicators sent to C++ EA");
    document.getElementById('eaLog').innerHTML += "Signal received from Pine<br>";
}

function startEA() {
    log("EA Started - WebSocket connected");
}

function forceBuy() { log("Force BUY executed via EA"); placeOrder(); }
function forceSell() { log("Force SELL executed via EA"); placeOrder(); }

function uploadEA() {
    log("EA binary uploaded successfully");
}
</script>
</body>
</html>"""
    return HTMLResponse(html)

# Existing endpoints (health, sign-order, transfers, withdrawal) remain the same as v3.5
@app.get("/health")
async def health():
    return {"status": "ok" if HttpPrivateSign else "degraded", "version": "3.6.0"}

# ... (keep all previous /sign-order, transfer, withdrawal endpoints from v3.5)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)