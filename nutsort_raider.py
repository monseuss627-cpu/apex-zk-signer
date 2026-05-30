#!/usr/bin/env python3
"""
Single-file Trading Signal Processor
- Embeds C++ math engine (auto-compiles)
- Public price feed (ApeX + Binance)
- Improved compilation robustness
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

# ====================== COMPATIBILITY FIX ======================
import inspect
if not hasattr(inspect, "getargspec"):
    print("⚠️  Applying inspect.getargspec compatibility shim for Python 3.11+")
    inspect.getargspec = inspect.getfullargspec

if not hasattr(inspect, "formatargspec"):
    def _formatargspec(*args, **kwargs):
        return inspect.formatannotation(*args, **kwargs) if hasattr(inspect, 'formatannotation') else str(args)
    inspect.formatargspec = _formatargspec
# ============================================================

# ========== Embedded C++ Source ==========
CPP_SOURCE = '''#include <iostream>
#include <string>
#include <cmath>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <sstream>

using fp_t = long double;

struct Signal {
    std::string symbol;
    fp_t old_price;
    fp_t new_price;
    fp_t increment;
    fp_t leverage;
    fp_t percent;
    std::string timestamp;
};

fp_t calculateOutput(const Signal& s) {
    fp_t price_diff = s.new_price - s.old_price;
    if (std::abs(price_diff) < 1e-15L) price_diff = 1e-15L;
    fp_t step1 = s.increment * s.leverage;
    fp_t step2 = step1 * (s.percent / 100.0L);
    fp_t intermediate = step2 / price_diff;
    fp_t final = (intermediate / 1000.0L) * 1e6L;
    return final;
}

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        Signal sig;
        auto extract = [&](const std::string& key) -> std::string {
            size_t pos = line.find("\\"" + key + "\\"");
            if (pos == std::string::npos) return "";
            pos = line.find(":", pos);
            if (pos == std::string::npos) return "";
            pos++;
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\\t')) pos++;
            if (line[pos] == '\\"') {
                size_t end = line.find("\\"", pos+1);
                return line.substr(pos+1, end-pos-1);
            } else {
                size_t end = pos;
                while (end < line.size() && (std::isdigit(line[end]) || line[end]=='.' || line[end]=='-' || line[end]=='e' || line[end]=='E')) end++;
                return line.substr(pos, end-pos);
            }
        };
        sig.symbol = extract("symbol");
        sig.old_price = std::stold(extract("old_price"));
        sig.new_price = std::stold(extract("new_price"));
        sig.increment = std::stold(extract("increment"));
        sig.leverage = std::stold(extract("leverage"));
        sig.percent = std::stold(extract("percent"));
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char ts[64];
        std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        sig.timestamp = ts;
        fp_t price_diff = sig.new_price - sig.old_price;
        fp_t step_result = sig.increment * sig.leverage * (sig.percent / 100.0L);
        fp_t final_output = calculateOutput(sig);
        std::cout << "{\\"type\\":\\"calc_result\\",\\"timestamp\\":\\"" << sig.timestamp
                  << "\\",\\"symbol\\":\\"" << sig.symbol
                  << "\\",\\"price_diff\\":" << std::setprecision(15) << price_diff
                  << ",\\"step_result\\":" << step_result
                  << ",\\"final_output\\":" << final_output
                  << "}" << std::endl;
        std::cout.flush();
    }
    return 0;
}
'''

# ========== Embedded HTML Frontend (same as before) ==========
HTML_FRONTEND = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trading Signal Processor</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>body { background: #0f172a; } .signal-log { max-height: 400px; overflow-y: auto; }</style>
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
                    <div><label class="block text-gray-400 text-sm">Symbol Pair</label><input type="text" id="sym" value="BTC-USDT" class="w-full bg-gray-700 rounded p-2"></div>
                    <div><label class="block text-gray-400 text-sm">Old Price (prev)</label><input type="number" id="oldPrice" step="any" class="w-full bg-gray-700 rounded p-2" value="60000.0"></div>
                    <div><label class="block text-gray-400 text-sm">New Price (auto from broker)</label><input type="number" id="newPrice" step="any" readonly class="w-full bg-gray-700 rounded p-2 bg-gray-900"></div>
                    <div><label class="block text-gray-400 text-sm">Increment (ii!!)</label><input type="number" id="increment" step="any" class="w-full bg-gray-700 rounded p-2" value="100.0"></div>
                    <div><label class="block text-gray-400 text-sm">Leverage (up to quadrillion)</label><input type="number" id="leverage" step="any" class="w-full bg-gray-700 rounded p-2" value="10.0"></div>
                    <div><label class="block text-gray-400 text-sm">Percent (%)</label><input type="number" id="percent" step="any" class="w-full bg-gray-700 rounded p-2" value="5.0"></div>
                </div>
                <div class="mt-6 border-t border-gray-700 pt-4">
                    <h3 class="text-lg font-semibold mb-2">📈 Calculated Results</h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div><label class="text-gray-400">Multiplied & Percent Calc (Step)</label><div id="stepResult" class="text-2xl font-mono text-green-400">--</div></div>
                        <div><label class="text-gray-400">Final Answer / Output</label><div id="finalOutput" class="text-2xl font-mono text-blue-400">--</div></div>
                        <div><label class="text-gray-400">Price Difference (Δ)</label><div id="priceDiff" class="text-xl font-mono">--</div></div>
                        <div><label class="text-gray-400">Date/Time (signal)</label><div id="timestamp" class="text-sm font-mono">--</div></div>
                    </div>
                </div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4">
                <h2 class="text-xl font-bold mb-2">📜 Signal Log</h2>
                <div id="logList" class="signal-log space-y-2 text-sm"><div class="text-gray-500">Waiting for signals...</div></div>
            </div>
        </div>
        <div class="mt-4 flex space-x-3">
            <button id="startBtn" class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded">▶ Start Bot</button>
            <button id="stopBtn" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded">⏹ Stop Bot</button>
            <button id="manualTrigger" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded">🔁 Manual Trigger</button>
        </div>
    </div>
    <script>
        let ws = null, running = false;
        function connectWebSocket() {
            ws = new WebSocket("ws://localhost:8000/ws");
            ws.onopen = () => { document.getElementById("status").innerText = "Connected"; document.getElementById("status").classList.remove("text-yellow-400"); document.getElementById("status").classList.add("text-green-400"); };
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.type === "price_update") { 
                    document.getElementById("newPrice").value = data.price; 
                    document.getElementById("currentPrice").innerText = parseFloat(data.price).toFixed(2);
                    if(running) triggerCalculation(); 
                }
                else if (data.type === "calc_result") {
                    document.getElementById("stepResult").innerText = parseFloat(data.step_result).toFixed(6);
                    document.getElementById("finalOutput").innerText = parseFloat(data.final_output).toFixed(2);
                    document.getElementById("priceDiff").innerText = parseFloat(data.price_diff).toFixed(4);
                    document.getElementById("timestamp").innerText = data.timestamp;
                    const logDiv = document.getElementById("logList"); 
                    const entry = document.createElement("div");
                    entry.className = "border-b border-gray-700 pb-1"; 
                    entry.innerHTML = `<span class="text-gray-400">${data.timestamp}</span> ${data.symbol} | Δ: ${parseFloat(data.price_diff).toFixed(4)} | Out: ${parseFloat(data.final_output).toFixed(2)}`;
                    logDiv.prepend(entry); 
                    if(logDiv.children.length > 50) logDiv.removeChild(logDiv.lastChild);
                }
            };
            ws.onclose = () => { document.getElementById("status").innerText = "Disconnected"; document.getElementById("status").classList.remove("text-green-400"); document.getElementById("status").classList.add("text-yellow-400"); setTimeout(connectWebSocket, 3000); };
        }
        function triggerCalculation() {
            const payload = { 
                symbol: document.getElementById("sym").value, 
                old_price: parseFloat(document.getElementById("oldPrice").value), 
                new_price: parseFloat(document.getElementById("newPrice").value), 
                increment: parseFloat(document.getElementById("increment").value), 
                leverage: parseFloat(document.getElementById("leverage").value), 
                percent: parseFloat(document.getElementById("percent").value) 
            };
            if(ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type:"calc_request", data:payload}));
        }
        document.getElementById("startBtn").onclick = () => { running = true; if(ws) ws.send(JSON.stringify({type:"start_bot"})); };
        document.getElementById("stopBtn").onclick = () => { running = false; if(ws) ws.send(JSON.stringify({type:"stop_bot"})); };
        document.getElementById("manualTrigger").onclick = triggerCalculation;
        connectWebSocket();
    </script>
</body>
</html>
'''

# ========== Improved Compilation ==========
def compile_cpp():
    cpp_path = Path("signal_core.cpp")
    exe_path = Path("signal_core")

    # Always ensure source file exists
    if not cpp_path.exists():
        print("📝 Writing C++ source file...")
        cpp_path.write_text(CPP_SOURCE)

    # Check if executable already exists and is recent
    if exe_path.exists():
        cpp_mtime = cpp_path.stat().st_mtime
        exe_mtime = exe_path.stat().st_mtime
        if exe_mtime > cpp_mtime:
            print("✅ Using existing compiled C++ core")
            return str(exe_path)

    print("🔨 Compiling C++ core (requires g++)...")
    try:
        result = subprocess.run(
            ["g++", "-std=c++17", "-O2", "-o", str(exe_path), str(cpp_path)],
            capture_output=True,
            text=True,
            check=True
        )
        print("✅ C++ core compiled successfully.")
        return str(exe_path)
    except FileNotFoundError:
        print("❌ Error: g++ compiler not found!")
        print("   Please install g++:")
        print("   Ubuntu/Debian: sudo apt install g++")
        print("   macOS: xcode-select --install")
        print("   Windows: Install MinGW or use WSL")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("❌ Compilation failed:")
        print(e.stderr)
        sys.exit(1)

# ========== Main Application ==========
async def main():
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse
    import uvicorn
    from apexomni.http_public import HttpPublic
    from apexomni.constants import APEX_OMNI_HTTP_MAIN

    SYMBOL = "BTC-USDT"
    RATE_LIMIT_SEC = 1.0
    last_signal_time = 0
    bot_running = False
    last_price = None

    # Public ApeX client
    try:
        apex_public = HttpPublic(APEX_OMNI_HTTP_MAIN)
        print("✅ ApeX Omni public feed ready")
    except Exception as e:
        print(f"⚠️ ApeX init warning: {e}")
        apex_public = None

    exe_path = compile_cpp()

    cpp_proc = subprocess.Popen(
        [exe_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    class Manager:
        def __init__(self):
            self.active = set()
        async def connect(self, ws):
            await ws.accept()
            self.active.add(ws)
        def disconnect(self, ws):
            self.active.discard(ws)
        async def broadcast(self, msg):
            for ws in list(self.active):
                try:
                    await ws.send_text(msg)
                except:
                    pass

    manager = Manager()

    def read_cpp_output():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        while True:
            line = cpp_proc.stdout.readline()
            if not line:
                break
            asyncio.run_coroutine_threadsafe(manager.broadcast(line.strip()), loop)

    threading.Thread(target=read_cpp_output, daemon=True).start()

    async def fetch_price():
        if apex_public:
            try:
                ticker = apex_public.ticker_v3(symbol=SYMBOL)
                price = float(ticker.get('price') or ticker.get('lastPrice') or 0)
                if price > 0:
                    return price
            except:
                pass
        # Binance fallback
        try:
            import requests
            r = requests.get("https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT", timeout=4)
            return float(r.json()["price"])
        except:
            import random
            return 60000 + random.uniform(-400, 400)

    async def price_monitor():
        nonlocal last_signal_time, bot_running, last_price
        while True:
            if bot_running:
                price = await fetch_price()
                if price:
                    await manager.broadcast(json.dumps({"type": "price_update", "price": price}))
                    now = time.time()
                    if (now - last_signal_time >= RATE_LIMIT_SEC and last_price and abs(price - last_price) > 1e-6):
                        signal = {
                            "symbol": SYMBOL,
                            "old_price": last_price,
                            "new_price": price,
                            "increment": 100.0,
                            "leverage": 10.0,
                            "percent": 5.0
                        }
                        if cpp_proc.stdin:
                            cpp_proc.stdin.write(json.dumps(signal) + "\n")
                            cpp_proc.stdin.flush()
                        last_signal_time = now
                    last_price = price
            await asyncio.sleep(1.2)

    app = FastAPI()

    @app.get("/")
    async def get_index():
        return HTMLResponse(HTML_FRONTEND)

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                msg = json.loads(data)
                if msg["type"] == "start_bot":
                    nonlocal bot_running, last_price
                    bot_running = True
                    price = await fetch_price()
                    if price:
                        last_price = price
                        await manager.broadcast(json.dumps({"type": "price_update", "price": price}))
                elif msg["type"] == "stop_bot":
                    bot_running = False
                elif msg["type"] == "calc_request":
                    if cpp_proc.stdin:
                        cpp_proc.stdin.write(json.dumps(msg["data"]) + "\n")
                        cpp_proc.stdin.flush()
        except WebSocketDisconnect:
            manager.disconnect(websocket)

    asyncio.create_task(price_monitor())

    print("🚀 Server starting at http://0.0.0.0:8000")
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())