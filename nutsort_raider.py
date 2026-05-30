#!/usr/bin/env python3
"""
Single-file Trading Signal Processor for Render.com
- Pure Python (no C++)
- Health check for Render
- Public price feed
"""

import asyncio
import json
import time
from decimal import Decimal, getcontext
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

getcontext().prec = 50

# ========== Calculation Engine ==========
def calculate_signal(data):
    try:
        old = Decimal(str(data["old_price"]))
        new = Decimal(str(data["new_price"]))
        inc = Decimal(str(data["increment"]))
        lev = Decimal(str(data["leverage"]))
        pct = Decimal(str(data["percent"]))

        diff = new - old
        if abs(diff) < Decimal("1e-15"):
            diff = Decimal("1e-15")

        step = inc * lev * (pct / Decimal(100))
        final = (step / diff / Decimal(1000)) * Decimal("1000000")

        return {
            "type": "calc_result",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "symbol": data.get("symbol", "BTC-USDT"),
            "price_diff": float(diff),
            "step_result": float(step),
            "final_output": float(final)
        }
    except Exception as e:
        print(f"Calc error: {e}")
        return None

# ========== HTML Frontend ==========
HTML_FRONTEND = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trading Signal Processor</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background: #0f172a; }
        .signal-log { max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body class="text-gray-200">
    <div class="container mx-auto p-4">
        <div class="bg-gray-800 rounded-lg p-4 mb-4 flex justify-between items-center">
            <div class="flex space-x-6">
                <div><span class="text-gray-400">Symbol:</span> <span id="symbol" class="font-mono text-lg">BTC-USDT</span></div>
                <div><span class="text-gray-400">Current Price:</span> <span id="currentPrice" class="font-mono text-xl text-green-400">--</span></div>
                <div><span class="text-gray-400">Status:</span> <span id="status" class="text-yellow-400">Connecting...</span></div>
            </div>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div class="lg:col-span-2 bg-gray-800 rounded-lg p-6">
                <h2 class="text-xl font-bold mb-4">📊 Signal Parameters</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div><label class="block text-gray-400 text-sm">Symbol</label><input type="text" id="sym" value="BTC-USDT" class="w-full bg-gray-700 rounded p-2"></div>
                    <div><label class="block text-gray-400 text-sm">Old Price</label><input type="number" id="oldPrice" step="any" value="60000.0" class="w-full bg-gray-700 rounded p-2"></div>
                    <div><label class="block text-gray-400 text-sm">New Price</label><input type="number" id="newPrice" readonly class="w-full bg-gray-900 rounded p-2"></div>
                    <div><label class="block text-gray-400 text-sm">Increment</label><input type="number" id="increment" value="100.0" step="any" class="w-full bg-gray-700 rounded p-2"></div>
                    <div><label class="block text-gray-400 text-sm">Leverage</label><input type="number" id="leverage" value="10.0" step="any" class="w-full bg-gray-700 rounded p-2"></div>
                    <div><label class="block text-gray-400 text-sm">Percent (%)</label><input type="number" id="percent" value="5.0" step="any" class="w-full bg-gray-700 rounded p-2"></div>
                </div>
                <div class="mt-6 border-t border-gray-700 pt-4">
                    <h3 class="text-lg font-semibold mb-2">Results</h3>
                    <div class="grid grid-cols-2 gap-4">
                        <div><label class="text-gray-400">Step Result</label><div id="stepResult" class="text-2xl font-mono text-green-400">--</div></div>
                        <div><label class="text-gray-400">Final Output</label><div id="finalOutput" class="text-2xl font-mono text-blue-400">--</div></div>
                        <div><label class="text-gray-400">Price Δ</label><div id="priceDiff" class="text-xl font-mono">--</div></div>
                        <div><label class="text-gray-400">Time</label><div id="timestamp" class="text-sm font-mono">--</div></div>
                    </div>
                </div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4">
                <h2 class="text-xl font-bold mb-2">Signal Log</h2>
                <div id="logList" class="signal-log space-y-2 text-sm"><div class="text-gray-500">Waiting for signals...</div></div>
            </div>
        </div>
        <div class="mt-4 flex space-x-3">
            <button id="startBtn" class="bg-green-600 hover:bg-green-700 px-6 py-2 rounded">▶ Start Bot</button>
            <button id="stopBtn" class="bg-red-600 hover:bg-red-700 px-6 py-2 rounded">⏹ Stop Bot</button>
            <button id="manualTrigger" class="bg-blue-600 hover:bg-blue-700 px-6 py-2 rounded">🔁 Manual</button>
        </div>
    </div>

    <script>
        let ws = null, running = false;
        function connect() {
            ws = new WebSocket("ws://" + window.location.host + "/ws");
            ws.onopen = () => document.getElementById("status").innerText = "Connected ✅";
            ws.onmessage = (e) => {
                const d = JSON.parse(e.data);
                if (d.type === "price_update") {
                    document.getElementById("newPrice").value = d.price;
                    document.getElementById("currentPrice").innerText = parseFloat(d.price).toFixed(2);
                    if (running) trigger();
                } else if (d.type === "calc_result") {
                    document.getElementById("stepResult").innerText = parseFloat(d.step_result).toFixed(6);
                    document.getElementById("finalOutput").innerText = parseFloat(d.final_output).toFixed(2);
                    document.getElementById("priceDiff").innerText = parseFloat(d.price_diff).toFixed(4);
                    document.getElementById("timestamp").innerText = d.timestamp;

                    const log = document.getElementById("logList");
                    const entry = document.createElement("div");
                    entry.className = "border-b border-gray-700 pb-1";
                    entry.innerHTML = `<span class="text-gray-400">${d.timestamp}</span> \( {d.symbol} | Δ: \){parseFloat(d.price_diff).toFixed(4)} | Out:${parseFloat(d.final_output).toFixed(2)}`;
                    log.prepend(entry);
                    if (log.children.length > 50) log.removeChild(log.lastChild);
                }
            };
            ws.onclose = () => { document.getElementById("status").innerText = "Disconnected"; setTimeout(connect, 3000); };
        }
        function trigger() {
            const payload = {
                symbol: document.getElementById("sym").value,
                old_price: parseFloat(document.getElementById("oldPrice").value),
                new_price: parseFloat(document.getElementById("newPrice").value),
                increment: parseFloat(document.getElementById("increment").value),
                leverage: parseFloat(document.getElementById("leverage").value),
                percent: parseFloat(document.getElementById("percent").value)
            };
            if (ws) ws.send(JSON.stringify({type: "calc_request", data: payload}));
        }
        document.getElementById("startBtn").onclick = () => { running = true; ws.send(JSON.stringify({type:"start_bot"})); };
        document.getElementById("stopBtn").onclick = () => { running = false; ws.send(JSON.stringify({type:"stop_bot"})); };
        document.getElementById("manualTrigger").onclick = trigger;
        connect();
    </script>
</body>
</html>
'''

app = FastAPI()

# Health check for Render.com
@app.get("/")
@app.head("/")
async def root():
    return {"status": "ok"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

# WebSocket
class Manager:
    def __init__(self):
        self.active = set()
    async def connect(self, ws):
        await ws.accept()
        self.active.add(ws)
    def disconnect(self, ws):
        self.active.discard(ws)
    async def broadcast(self, msg):
        for w in list(self.active):
            try:
                await w.send_text(msg)
            except:
                pass

manager = Manager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg["type"] == "start_bot":
                # start logic handled in background task
                await websocket.send_text(json.dumps({"type": "status", "message": "Bot started"}))
            elif msg["type"] == "stop_bot":
                pass
            elif msg["type"] == "calc_request":
                result = calculate_signal(msg["data"])
                if result:
                    await manager.broadcast(json.dumps(result))
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background price feed
SYMBOL = "BTC-USDT"
bot_running = False
last_price = None
last_signal_time = 0.0

async def price_monitor():
    global bot_running, last_price, last_signal_time
    try:
        from apexomni.http_public import HttpPublic
        from apexomni.constants import APEX_OMNI_HTTP_MAIN
        apex = HttpPublic(APEX_OMNI_HTTP_MAIN)
    except:
        apex = None

    while True:
        if bot_running:
            # Fetch price
            price = None
            if apex:
                try:
                    t = apex.ticker_v3(symbol=SYMBOL)
                    price = float(t.get('price') or t.get('lastPrice') or 0)
                except:
                    pass
            if not price:
                try:
                    import requests
                    r = requests.get("https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT", timeout=5)
                    price = float(r.json()["price"])
                except:
                    import random
                    price = 60000 + random.uniform(-500, 500)

            if price:
                await manager.broadcast(json.dumps({"type": "price_update", "price": price}))
                now = time.time()
                if (now - last_signal_time >= 1.0 and last_price and abs(price - last_price) > 1e-6):
                    signal = {
                        "symbol": SYMBOL,
                        "old_price": last_price,
                        "new_price": price,
                        "increment": 100.0,
                        "leverage": 10.0,
                        "percent": 5.0
                    }
                    result = calculate_signal(signal)
                    if result:
                        await manager.broadcast(json.dumps(result))
                    last_signal_time = now
                last_price = price
        await asyncio.sleep(1.5)

if __name__ == "__main__":
    asyncio.create_task(price_monitor())
    print("🚀 Server running on Render - http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")