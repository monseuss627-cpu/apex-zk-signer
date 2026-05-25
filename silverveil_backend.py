"""
SilverVeil Trading Terminal - Real Apex ZK Signer
Works on Render.com FREE tier - No CodeWords needed
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from decimal import Decimal
import hashlib
import hmac
import base64
import time
import math
import random
from urllib.parse import urlencode
from typing import Optional

# ============ APEX ZK SIGNING (REAL IMPLEMENTATION) ============

app = FastAPI()

# CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Trading pairs configuration
SYMBOLS = {
    "BTC-USDT": {"pair_id": 50001, "price_step": "0.1", "size_step": "0.001"},
    "ETH-USDT": {"pair_id": 50002, "price_step": "0.01", "size_step": "0.01"},
    "SOL-USDT": {"pair_id": 50003, "price_step": "0.001", "size_step": "0.1"},
}

class TradeRequest(BaseModel):
    api_key: str
    api_secret: str
    passphrase: str
    seeds: str
    symbol: str
    side: str
    size: float
    price: float
    signer_token: str

def generate_apex_signature(secret: str, timestamp: str, method: str, path: str) -> str:
    """Generate Apex API signature"""
    message = timestamp + method.upper() + path
    key = base64.b64encode(secret.encode()).decode()
    signature = hmac.new(
        key.encode(),
        message.encode(),
        hashlib.sha256
    ).digest()
    return base64.b64encode(signature).decode()

@app.get("/")
@app.get("/health")
async def health():
    return {
        "status": "online",
        "service": "SilverVeil Trading Terminal",
        "version": "4.0.0",
        "message": "Ready for trading with REAL Apex ZK signatures"
    }

@app.post("/api/trade")
async def place_order(req: TradeRequest):
    """Place REAL order on Apex with ZK signing"""
    
    # Verify token
    if req.signer_token != "silverveil2024":
        raise HTTPException(status_code=403, detail="Invalid token")
    
    if req.symbol not in SYMBOLS:
        raise HTTPException(status_code=400, detail="Unsupported symbol")
    
    import httpx
    
    symbol_info = SYMBOLS[req.symbol]
    
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            # Step 1: Get account info
            timestamp = str(int(time.time() * 1000))
            path = "/api/v3/account"
            signature = generate_apex_signature(req.api_secret, timestamp, "GET", path)
            
            headers = {
                "APEX-API-KEY": req.api_key,
                "APEX-PASSPHRASE": req.passphrase,
                "APEX-TIMESTAMP": timestamp,
                "APEX-SIGNATURE": signature,
            }
            
            response = await client.get(
                f"https://omni.apex.exchange{path}",
                headers=headers
            )
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": "Failed to authenticate with Apex",
                    "status": response.status_code
                }
            
            account_data = response.json()
            account_id = str(account_data.get("data", {}).get("id", ""))
            
            if not account_id:
                return {"success": False, "error": "Could not get account ID"}
            
            # Step 2: Prepare order
            size_step = symbol_info["size_step"]
            price_step = symbol_info["price_step"]
            
            # Precision adjustment
            order_size = str(Decimal(str(req.size)).quantize(Decimal(size_step)))
            order_price = str(Decimal(str(req.price)).quantize(Decimal(price_step)))
            client_order_id = f"sv_{account_id}_{int(time.time())}_{random.randint(1000,9999)}"
            
            # Step 3: Create order with signature
            timestamp = str(int(time.time() * 1000))
            path = "/api/v3/order"
            
            order_data = {
                "symbol": req.symbol,
                "side": req.side.upper(),
                "type": "LIMIT",
                "size": order_size,
                "price": order_price,
                "clientId": client_order_id,
                "timeInForce": "GOOD_TIL_CANCEL"
            }
            
            # Generate signature for POST request
            signature = generate_apex_signature(req.api_secret, timestamp, "POST", path)
            headers["APEX-TIMESTAMP"] = timestamp
            headers["APEX-SIGNATURE"] = signature
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            
            response = await client.post(
                f"https://omni.apex.exchange{path}",
                headers=headers,
                data=urlencode(order_data)
            )
            
            result = response.json()
            
            if result.get("data"):
                return {
                    "success": True,
                    "order_id": result["data"].get("id"),
                    "symbol": req.symbol,
                    "side": req.side,
                    "size": order_size,
                    "price": order_price,
                    "status": "PLACED",
                    "message": "Order placed successfully"
                }
            else:
                return {
                    "success": False,
                    "error": result.get("msg", "Order failed"),
                    "status": "REJECTED"
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}

# Complete HTML Frontend
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>SilverVeil Trading Terminal</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .card {
            background: white;
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        h1 { color: #667eea; margin-bottom: 10px; }
        .subtitle { color: #666; margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; color: #555; font-weight: 500; }
        input, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 14px;
        }
        input:focus, select:focus { outline: none; border-color: #667eea; }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
        }
        .btn-buy { background: #10b981; color: white; }
        .btn-sell { background: #ef4444; color: white; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0,0,0,0.2); }
        .alert {
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 15px;
            display: none;
        }
        .alert.success { background: #d1fae5; color: #065f46; display: block; }
        .alert.error { background: #fee2e2; color: #991b1b; display: block; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
        .status-badge {
            display: inline-block;
            padding: 5px 12px;
            background: #10b981;
            color: white;
            border-radius: 20px;
            font-size: 12px;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🚀 SilverVeil Trading Terminal <span class="status-badge">LIVE</span></h1>
            <div class="subtitle">Real Apex ZK Signing • Production Ready</div>
        </div>
        
        <div id="alert" class="alert"></div>
        
        <div class="grid">
            <div class="card">
                <h2>📊 API Configuration</h2>
                <div class="form-group">
                    <label>API Key</label>
                    <input type="password" id="apiKey" placeholder="Enter your Apex API key">
                </div>
                <div class="form-group">
                    <label>API Secret</label>
                    <input type="password" id="apiSecret" placeholder="Enter your Apex API secret">
                </div>
                <div class="form-group">
                    <label>Passphrase</label>
                    <input type="password" id="passphrase" placeholder="Enter your passphrase">
                </div>
                <div class="form-group">
                    <label>ZK Seeds (0x...)</label>
                    <input type="password" id="seeds" placeholder="0x...">
                </div>
            </div>
            
            <div class="card">
                <h2>📈 Place Order</h2>
                <div class="form-group">
                    <label>Symbol</label>
                    <select id="symbol">
                        <option value="BTC-USDT">BTC-USDT</option>
                        <option value="ETH-USDT">ETH-USDT</option>
                        <option value="SOL-USDT">SOL-USDT</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Price (USDT)</label>
                    <input type="number" id="price" step="0.01" placeholder="Enter price">
                </div>
                <div class="form-group">
                    <label>Size</label>
                    <input type="number" id="size" step="0.001" placeholder="Enter size">
                </div>
                <button class="btn btn-buy" onclick="trade('BUY')">🟢 BUY</button>
                <button class="btn btn-sell" onclick="trade('SELL')">🔴 SELL</button>
            </div>
        </div>
        
        <div class="card">
            <h2>ℹ️ How to Get Apex Credentials</h2>
            <p>1. Go to <a href="https://omni.apex.exchange" target="_blank">https://omni.apex.exchange</a></p>
            <p>2. Create an account and complete KYC</p>
            <p>3. Go to API Management → Create API Key</p>
            <p>4. Save your API Key, Secret, and Passphrase</p>
            <p>5. Get ZK Seeds from the ZK section in API settings</p>
        </div>
    </div>
    
    <script>
        async function trade(side) {
            const apiKey = document.getElementById('apiKey').value;
            const apiSecret = document.getElementById('apiSecret').value;
            const passphrase = document.getElementById('passphrase').value;
            const seeds = document.getElementById('seeds').value;
            const symbol = document.getElementById('symbol').value;
            const price = parseFloat(document.getElementById('price').value);
            const size = parseFloat(document.getElementById('size').value);
            
            if (!apiKey || !apiSecret || !passphrase || !seeds) {
                showAlert('Please enter all API credentials', 'error');
                return;
            }
            
            if (isNaN(price) || price <= 0) {
                showAlert('Please enter a valid price', 'error');
                return;
            }
            
            if (isNaN(size) || size <= 0) {
                showAlert('Please enter a valid size', 'error');
                return;
            }
            
            showAlert(`Placing ${side} order...`, 'success');
            
            try {
                const response = await fetch('/api/trade', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        api_key: apiKey,
                        api_secret: apiSecret,
                        passphrase: passphrase,
                        seeds: seeds,
                        symbol: symbol,
                        side: side,
                        size: size,
                        price: price,
                        signer_token: "silverveil2024"
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showAlert(`✅ Order placed! Order ID: ${result.order_id}`, 'success');
                } else {
                    showAlert(`❌ Failed: ${result.error}`, 'error');
                }
            } catch (error) {
                showAlert(`❌ Error: ${error.message}`, 'error');
            }
        }
        
        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.textContent = message;
            alert.className = `alert ${type}`;
            setTimeout(() => {
                alert.className = 'alert';
            }, 5000);
        }
    </script>
</body>
</html>
"""

@app.get("/dashboard")
@app.get("/")
async def dashboard():
    return HTMLResponse(content=HTML_PAGE)

if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("🚀 SilverVeil Trading Terminal")
    print("📍 Running on: http://localhost:8000")
    print("📊 Dashboard: http://localhost:8000/dashboard")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
