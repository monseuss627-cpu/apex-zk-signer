import sys
from flask import Flask, render_template_string

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>Nutsort Raider™ Pro | Apex Monitor Terminal</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            user-select: none;
        }

        body {
            background: radial-gradient(circle at 20% 30%, #0a0c12, #010101);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Inter', 'Segoe UI', 'Courier New', monospace;
            padding: 20px;
        }

        /* MAIN TERMINAL PANEL */
        .raider-panel {
            max-width: 620px;
            width: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(8px);
            border: 1px solid rgba(0, 255, 191, 0.35);
            border-radius: 2rem;
            padding: 1.2rem 1.5rem 1.8rem;
            box-shadow: 0 20px 40px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,255,200,0.1) inset, 0 0 12px rgba(0,255,191,0.2);
            transition: all 0.2s;
        }

        /* header zone */
        .status-bar {
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #2a2e3a;
            padding-bottom: 10px;
            margin-bottom: 18px;
            font-size: 0.7rem;
            letter-spacing: 1px;
            color: #6effc8;
            font-weight: 500;
        }
        .live-badge {
            background: #00aa6e20;
            padding: 4px 12px;
            border-radius: 40px;
            border-left: 3px solid #0fdd88;
            font-family: monospace;
        }
        .trading-badge {
            background: #15221c;
            padding: 4px 12px;
            border-radius: 40px;
            color: #9effcf;
        }

        h1 {
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.3px;
            background: linear-gradient(135deg, #c0ffdc, #72f0b0);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            display: inline-block;
            margin-bottom: 8px;
        }
        .sub {
            font-size: 0.65rem;
            color: #7c8e8a;
            letter-spacing: 0.5px;
            margin-top: -4px;
            margin-bottom: 20px;
            border-left: 2px solid #00cc88;
            padding-left: 12px;
        }

        /* SYMBOL ASSET */
        .asset-row {
            background: #0e1219;
            padding: 12px 18px;
            border-radius: 60px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            border: 1px solid #2f3e3a;
            box-shadow: inset 0 1px 3px #00000030, 0 2px 3px #00ffbf10;
        }
        .asset-label {
            font-weight: 500;
            color: #bbf0da;
            font-size: 0.85rem;
        }
        .asset-symbol {
            font-weight: 800;
            font-size: 1.4rem;
            letter-spacing: 1px;
            background: linear-gradient(145deg, #d4ffea, #87eec2);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }
        .increment-price {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.7rem;
            font-weight: 700;
            color: #f0ffe0;
            text-shadow: 0 0 6px #0affb0;
            letter-spacing: 1px;
        }

        /* RESULT MONSTER DISPLAY */
        .result-screen {
            background: #03060c;
            border-radius: 28px;
            padding: 16px 20px;
            margin: 15px 0 18px 0;
            text-align: right;
            border: 1px solid #2effbc30;
            box-shadow: inset 0 4px 12px #00000055, 0 6px 12px #00000030;
        }
        .result-label {
            font-size: 0.7rem;
            color: #5cffb0;
            letter-spacing: 2px;
            display: flex;
            justify-content: space-between;
        }
        .calc-answer {
            font-size: 2.5rem;
            font-weight: 800;
            font-family: 'Courier New', monospace;
            color: #bcfcd8;
            word-break: break-word;
            line-height: 1.2;
        }
        .snapshot-timer {
            font-family: monospace;
            font-size: 0.8rem;
            background: #10221c;
            padding: 6px 12px;
            border-radius: 60px;
            color: #aaffdd;
        }

        /* PERCENTAGE + LIVE FEED GRID */
        .live-feed-strip {
            background: #0b0f16;
            border-radius: 24px;
            padding: 12px 18px;
            margin-bottom: 20px;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            justify-content: space-between;
            border: 1px solid #2d4a3e;
        }
        .percent-control {
            background: #00000055;
            border-radius: 48px;
            padding: 6px 12px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .percent-val {
            font-size: 2rem;
            font-weight: 800;
            background: #000000aa;
            padding: 0 15px;
            border-radius: 40px;
            color: #b0ffdc;
            min-width: 80px;
            text-align: center;
        }
        .pos-neg {
            display: flex;
            gap: 12px;
        }
        .pos-neg button {
            background: #192e26;
            border: none;
            color: #bbffdd;
            font-weight: bold;
            font-size: 1.4rem;
            width: 48px;
            border-radius: 40px;
            cursor: pointer;
            transition: 0.07s linear;
        }
        .pos-neg button:active {
            background: #2b5e49;
            transform: scale(0.96);
        }

        /* INCREMENT PRICE CARD */
        .price-increment {
            background: #00000066;
            border-radius: 36px;
            padding: 6px 18px;
            text-align: center;
        }
        .price-increment span:first-child {
            font-size: 0.7rem;
            color: #80e0bc;
        }
        .inc-value {
            font-size: 1.5rem;
            font-weight: bold;
            color: #e2ffef;
        }

        /* CALCULATOR KEYPAD (exact replica style) */
        .keypad {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin: 20px 0 18px;
        }
        .key-btn {
            background: #11161f;
            border: none;
            padding: 14px 0;
            font-size: 1.3rem;
            font-weight: 600;
            font-family: monospace;
            color: #bcffde;
            border-radius: 28px;
            box-shadow: 0 2px 0 #2f6d56;
            transition: 0.04s linear;
            cursor: pointer;
        }
        .key-btn:active {
            transform: translateY(2px);
            box-shadow: none;
            background: #1b3a30;
        }
        .operator {
            background: #1f392f;
            color: #ffd98c;
        }
        .clear-btn {
            background: #3a2420;
            color: #ffbea3;
        }

        /* PLACE BUTTON (main trigger) */
        .place-holder {
            margin-top: 12px;
            text-align: center;
        }
        .place-btn {
            background: linear-gradient(95deg, #009970, #0add9a);
            border: none;
            width: 100%;
            padding: 18px 0;
            font-size: 1.4rem;
            font-weight: 800;
            letter-spacing: 2px;
            color: #010b07;
            border-radius: 60px;
            font-family: monospace;
            cursor: pointer;
            box-shadow: 0 0 12px #00ffb360;
            transition: 0.08s linear;
            text-transform: uppercase;
        }
        .place-btn:active {
            transform: scale(0.98);
            background: linear-gradient(95deg, #00b37a, #0bf59f);
        }
        .place-btn.disabled {
            opacity: 0.6;
            pointer-events: none;
            filter: grayscale(0.2);
        }
        .footer-note {
            margin-top: 16px;
            font-size: 0.65rem;
            text-align: center;
            color: #4b6f63;
            border-top: 0.5px solid #204e3f;
            padding-top: 12px;
        }
        .flash-msg {
            background: #00885620;
            border-radius: 40px;
            font-size: 0.7rem;
            padding: 6px;
            margin-top: 6px;
        }
        button {
            cursor: pointer;
        }
        input {
            background: transparent;
            border: none;
            color: #b1ffdb;
            font-size: 1.4rem;
            width: 80px;
            text-align: center;
            font-weight: bold;
        }
        input:focus {
            outline: none;
        }
    </style>
</head>
<body>
<div class="raider-panel">
    <div class="status-bar">
        <div class="live-badge">⚡ LIVE FEED ROUTED — INCREMENT PLACE PAUSES STREAM</div>
        <div class="trading-badge">LIVE • TRADING</div>
    </div>
    <h1>Nutsort Raider™ Pro Calculator</h1>
    <div class="sub">OMNI · REAL TIME · V3.1.0 — SNAPSHOT ENGINE</div>

    <!-- symbol pair increment display -->
    <div class="asset-row">
        <span class="asset-label">PERPETUAL SYMBOL ASSET</span>
        <span class="asset-symbol">BTC-USDT</span>
        <div class="increment-price" id="liveIncrementPrice">--</div>
    </div>

    <!-- result & snapshot section -->
    <div class="result-screen">
        <div class="result-label">
            <span>📐 RESULT (PRICE × %)</span>
            <span id="snapshotTimerDisplay" class="snapshot-timer">⚡ ready</span>
        </div>
        <div class="calc-answer" id="calculationResult">0.00</div>
        <div class="flash-msg" id="snapshotStatusMsg">↻ LIVE MODE · PLACE TO FREEZE 45S</div>
    </div>

    <!-- % value and increment block -->
    <div class="live-feed-strip">
        <div class="percent-control">
            <span style="color:#92ffcb;">% VALUE</span>
            <div class="percent-val" id="percentValueDisplay">5</div>
            <div class="pos-neg">
                <button id="posBtn">+</button>
                <button id="negBtn">-</button>
            </div>
        </div>
        <div class="price-increment">
            <span>INCREMENT BTC-USD</span><br>
            <span class="inc-value" id="btcPriceIncrement">--</span>
        </div>
    </div>

    <!-- FULL KEYPAD (matching reference images) -->
    <div class="keypad">
        <button class="key-btn" data-num="7">7</button>
        <button class="key-btn" data-num="8">8</button>
        <button class="key-btn" data-num="9">9</button>
        <button class="key-btn operator" data-op="divide">/</button>

        <button class="key-btn" data-num="4">4</button>
        <button class="key-btn" data-num="5">5</button>
        <button class="key-btn" data-num="6">6</button>
        <button class="key-btn operator" data-op="multiply">*</button>

        <button class="key-btn" data-num="1">1</button>
        <button class="key-btn" data-num="2">2</button>
        <button class="key-btn" data-num="3">3</button>
        <button class="key-btn operator" data-op="minus">-</button>

        <button class="key-btn clear-btn" id="clearPercent">C</button>
        <button class="key-btn" data-num="0">0</button>
        <button class="key-btn" id="percentKey">%</button>
        <button class="key-btn operator" data-op="plus">+</button>
    </div>

    <!-- PLACE BUTTON (the only core interactive trigger for snapshot) -->
    <div class="place-holder">
        <button id="placeSnapshotBtn" class="place-btn">PLACE · HOLD FEED 45S</button>
    </div>
    <div class="footer-note">
        ⏲️ 45s snapshot freezes calc · price × % = result<br>
        🧠 LIVE INCREMENT PRICE FROM BINANCE WS (low latency)
    </div>
</div>

<script>
    // --------------------------------------------
    // REAL-TIME PRICE FEED (Binance WebSocket low latency)
    // --------------------------------------------
    let currentPrice = 0;
    let percentValue = 5;       // default %
    let snapshotActive = false;
    let snapshotEndTime = 0;
    let frozenResult = 0;
    let snapshotPriceUsed = 0;
    let snapshotPercentUsed = 0;
    let countdownInterval = null;
    
    // DOM elements
    const liveIncSpan = document.getElementById('liveIncrementPrice');
    const btcIncSpan = document.getElementById('btcPriceIncrement');
    const resultDiv = document.getElementById('calculationResult');
    const percentDisplaySpan = document.getElementById('percentValueDisplay');
    const snapshotTimerSpan = document.getElementById('snapshotTimerDisplay');
    const snapshotMsgSpan = document.getElementById('snapshotStatusMsg');
    const placeBtn = document.getElementById('placeSnapshotBtn');
    
    // Helper: update displayed percent value
    function updatePercentUI() {
        percentDisplaySpan.innerText = percentValue;
        // also update any input field? keep consistent
        if (!snapshotActive) {
            computeAndShowResult(currentPrice, percentValue);
        } else {
            // if snapshot active, result remains frozen, but we don't override UI result
            // just ensure the frozen result still displays
            resultDiv.innerText = formatNumber(frozenResult);
        }
    }
    
    // Format number with commas and decimals
    function formatNumber(num) {
        if (num === undefined || isNaN(num)) return "0.00";
        return num.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 });
    }
    
    // Live compute: price * (percent/100)
    function computeAndShowResult(price, percent) {
        if (price === 0) {
            resultDiv.innerText = "0.00";
            return;
        }
        let calc = price * (percent / 100);
        resultDiv.innerText = formatNumber(calc);
        return calc;
    }
    
    // Freeze snapshot logic (triggered by PLACE button)
    function start45sSnapshot() {
        if (snapshotActive) {
            // reset previous snapshot
            clearSnapshotTimer();
        }
        if (currentPrice === 0) {
            snapshotMsgSpan.innerText = "⚠️ waiting for price feed...";
            return;
        }
        // capture current price & percent
        snapshotPriceUsed = currentPrice;
        snapshotPercentUsed = percentValue;
        const computed = snapshotPriceUsed * (snapshotPercentUsed / 100);
        frozenResult = computed;
        resultDiv.innerText = formatNumber(frozenResult);
        snapshotActive = true;
        const now = Date.now();
        snapshotEndTime = now + 45000;
        
        // update UI
        snapshotMsgSpan.innerHTML = "🔒 SNAPSHOT ACTIVE · 45s FREEZE · NO ORDER";
        snapshotMsgSpan.style.color = "#fff0b0";
        placeBtn.classList.add('disabled');
        placeBtn.innerText = "⏳ SNAPSHOT LOCKED (45s)";
        startCountdownDisplay();
    }
    
    function startCountdownDisplay() {
        if (countdownInterval) clearInterval(countdownInterval);
        countdownInterval = setInterval(() => {
            if (!snapshotActive) {
                if (countdownInterval) clearInterval(countdownInterval);
                return;
            }
            const remaining = Math.max(0, snapshotEndTime - Date.now());
            if (remaining <= 0) {
                // snapshot finished
                clearSnapshotTimer();
                snapshotActive = false;
                snapshotMsgSpan.innerHTML = "✅ SNAPSHOT ENDED · LIVE MODE RESTORED";
                snapshotMsgSpan.style.color = "#6effc8";
                snapshotTimerSpan.innerText = "⚡ live";
                placeBtn.classList.remove('disabled');
                placeBtn.innerText = "PLACE · HOLD FEED 45S";
                // recalc with latest price & current percent
                computeAndShowResult(currentPrice, percentValue);
                return;
            }
            const seconds = Math.ceil(remaining / 1000);
            snapshotTimerSpan.innerText = `⏱️ ${seconds}s frozen`;
        }, 200);
    }
    
    function clearSnapshotTimer() {
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
    }
    
    // reset snapshot if expired after price update
    function checkSnapshotExpiry() {
        if (snapshotActive && Date.now() >= snapshotEndTime) {
            snapshotActive = false;
            snapshotMsgSpan.innerHTML = "🔄 SNAPSHOT DONE · LIVE MODE";
            snapshotMsgSpan.style.color = "#6effc8";
            snapshotTimerSpan.innerText = "⚡ live";
            placeBtn.classList.remove('disabled');
            placeBtn.innerText = "PLACE · HOLD FEED 45S";
            computeAndShowResult(currentPrice, percentValue);
            if (countdownInterval) clearInterval(countdownInterval);
        }
    }
    
    // price update from WebSocket (Binance)
    function setNewPrice(priceRaw) {
        let price = parseFloat(priceRaw);
        if (isNaN(price)) return;
        currentPrice = price;
        // update increment displays
        liveIncSpan.innerText = `$${currentPrice.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})}`;
        btcIncSpan.innerText = `$${currentPrice.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})}`;
        
        // if no snapshot active -> live recalculation
        if (!snapshotActive) {
            computeAndShowResult(currentPrice, percentValue);
        } else {
            // snapshot active: check expiry first, if expired then release
            checkSnapshotExpiry();
            if (!snapshotActive) {
                computeAndShowResult(currentPrice, percentValue);
            } else {
                // still frozen, keep frozenResult on screen
                resultDiv.innerText = formatNumber(frozenResult);
            }
        }
    }
    
    // WebSocket connection to Binance (BTCUSDT trade stream - ultra low latency)
    let ws = null;
    function initWebSocket() {
        if (ws) ws.close();
        ws = new WebSocket('wss://stream.binance.com:9443/ws/btcusdt@trade');
        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data && data.p) {
                    setNewPrice(data.p);
                }
            } catch(e) { /* silent */ }
        };
        ws.onerror = (err) => {
            console.warn("WS error, reconnecting...");
            setTimeout(initWebSocket, 2000);
        };
        ws.onclose = () => {
            setTimeout(initWebSocket, 2000);
        };
    }
    
    // KEYPAD & PERCENT HANDLERS
    // numeric keypad: update percent value
    function setPercentValue(newVal) {
        let val = newVal;
        if (isNaN(val)) val = percentValue;
        val = Math.min(100, Math.max(0, val));
        percentValue = val;
        updatePercentUI();
        if (!snapshotActive) {
            computeAndShowResult(currentPrice, percentValue);
        } else {
            // snapshot active: we do NOT modify frozenResult, but we store updated percent for after snapshot.
            // just keep frozen result.
            resultDiv.innerText = formatNumber(frozenResult);
        }
    }
    
    document.querySelectorAll('.key-btn[data-num]').forEach(btn => {
        btn.addEventListener('click', () => {
            if (snapshotActive) {
                snapshotMsgSpan.innerText = "🔒 Snapshot active, percent change after 45s";
                return;
            }
            const digit = btn.getAttribute('data-num');
            let newPercent = parseInt(percentValue.toString() + digit);
            if (newPercent > 100) newPercent = 100;
            setPercentValue(newPercent);
        });
    });
    
    document.getElementById('clearPercent').addEventListener('click', () => {
        if (snapshotActive) return;
        setPercentValue(0);
    });
    document.getElementById('percentKey').addEventListener('click', () => {
        if (snapshotActive) return;
        // set % as same (just style)
    });
    document.getElementById('posBtn').addEventListener('click', () => {
        if (snapshotActive) return;
        setPercentValue(percentValue + 1);
    });
    document.getElementById('negBtn').addEventListener('click', () => {
        if (snapshotActive) return;
        setPercentValue(percentValue - 1);
    });
    // operators (non functional UI but match design - they don't affect core snapshot but maintains replica)
    document.querySelectorAll('[data-op]').forEach(opBtn => {
        opBtn.addEventListener('click', (e) => {
            if(!snapshotActive) snapshotMsgSpan.innerText = "⚡ Live mode • use +/- or digits for %";
            else snapshotMsgSpan.innerText = "❄️ Snapshot frozen – wait 45s";
        });
    });
    
    // PLACE BUTTON: trigger 45s snapshot
    placeBtn.addEventListener('click', () => {
        if (snapshotActive) {
            snapshotMsgSpan.innerText = "⏳ snapshot already running, wait for release";
            return;
        }
        if (currentPrice === 0) {
            snapshotMsgSpan.innerText = "⚠️ waiting for live price data...";
            return;
        }
        start45sSnapshot();
    });
    
    // initial load
    initWebSocket();
    setPercentValue(5);
    computeAndShowResult(0, 5);
    // fallback to demo price if websocket delayed
    setTimeout(() => {
        if (currentPrice === 0) setNewPrice(73871.3);
    }, 1200);
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════╗
    ║  🚀 NUTSORT RAIDER™ PRO CALCULATOR           ║
    ║  LIVE PRICE FEED (Binance WebSocket)        ║
    ║  PLACE button → 45s snapshot (price × %)    ║
    ║  Access: http://localhost:5000              ║
    ╚══════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)