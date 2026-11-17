import os
import time
import httpx
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="Meme Hunter")

CHAIN = "56"
MIN_LIQUIDITY = 50000
MAX_SIGNALS = 3

state = {
    "items": [],
    "updated": None,
    "errors": []
}


def number(value):
    try:
        return float(value or 0)
    except:
        return 0


async def get_data(client, url, params=None):
    response = await client.get(
        url,
        params=params,
        timeout=20
    )
    response.raise_for_status()
    return response.json()


async def security_check(client, address):

    try:
        url = (
            "https://api.gopluslabs.io/api/v1/"
            "token_security/56"
        )

        data = await get_data(
            client,
            url,
            {"contract_addresses": address.lower()}
        )

        result = data.get("result", {})
        return result.get(address.lower(), {})

    except Exception:
        return {}


def analyze(pair, security):

    score = 0
    reasons = []
    risks = []

    liquidity = number(
        pair.get("liquidity", {}).get("usd")
    )

    volume = pair.get("volume", {})
    transactions = pair.get("txns", {})
    changes = pair.get("priceChange", {})

    buys = number(
        transactions.get("h1", {}).get("buys")
    )

    sells = number(
        transactions.get("h1", {}).get("sells")
    )

    vol1 = number(volume.get("h1"))
    vol24 = number(volume.get("h24"))

    if liquidity >= MIN_LIQUIDITY:
        score += 20
        reasons.append("نقدینگی مناسب")

    if buys + sells >= 20 and buys > sells * 1.15:
        score += 15
        reasons.append("غلبه خریداران")

    if vol24 > 0 and vol1 > vol24 / 24 * 1.25:
        score += 15
        reasons.append("افزایش حجم معاملات")

    price_change = number(changes.get("h1"))

    if 0 < price_change < 35:
        score += 10
        reasons.append("رشد کنترل شده")

    flags = {
        "is_honeypot": "احتمال Honeypot",
        "cannot_sell_all": "محدودیت فروش",
        "hidden_owner": "مالک مخفی",
        "is_blacklisted": "قابلیت بلک لیست",
        "selfdestruct": "خطر خودتخریبی",
        "can_take_back_ownership": "بازپس گیری مالکیت",
        "owner_change_balance": "تغییر موجودی کاربران"
    }

    for key, title in flags.items():

        if str(security.get(key, "0")) == "1":
            risks.append(title)

    if not security:
        risks.append("بررسی امنیت ناقص")

    if str(security.get("is_mintable", "0")) == "1":
        risks.append("قابلیت ساخت توکن جدید")

    if number(security.get("buy_tax")) > 0.05:
        risks.append("مالیات خرید بالا")

    if number(security.get("sell_tax")) > 0.05:
        risks.append("مالیات فروش بالا")

    score = max(0, score - len(risks) * 12)

    return {
        "score": min(100, score),
        "reasons": reasons,
        "risks": risks,
        "eligible": (
            score >= 65
            and not risks
            and bool(security)
        )
    }


@app.get("/", response_class=HTMLResponse)
async def home():

    return """
    <html lang="fa" dir="rtl">
    <meta charset="UTF-8">
    <meta name="viewport"
    content="width=device-width, initial-scale=1">

    <body style="
    background:#0b1020;
    color:white;
    font-family:Arial;
    padding:25px">

    <h1 style="color:#a78bfa">
    ▥ MEME HUNTER
    </h1>

    <h3>BNB Chain Scanner</h3>

    <p>حساب آزمایشی: 100 دلار</p>

    <button onclick="scan()">
    شروع اسکن بازار
    </button>

    <pre id="result"></pre>

    <script>
    async function scan(){

    document.getElementById("result").innerText=
    "در حال اسکن بازار...";

    let r=await fetch("/api/scan",{
    method:"POST"
    });

    let d=await r.json();

    document.getElementById("result").innerText=
    JSON.stringify(d,null,2);

    }
    </script>

    </body>
    </html>
    """


@app.post("/api/scan")
async def scan():

    items = []
    errors = []

    async with httpx.AsyncClient() as client:

        addresses = []

        for endpoint in [
            "token-boosts/latest/v1",
            "token-profiles/latest/v1"
        ]:

            try:

                data = await get_data(
                    client,
                    "https://api.dexscreener.com/"
                    + endpoint
                )

                addresses += [
                    x["tokenAddress"]
                    for x in data
                    if x.get("chainId") == "bsc"
                    and x.get("tokenAddress")
                ]

            except Exception as error:
                errors.append(str(error))

        addresses = list(dict.fromkeys(addresses))[:30]

        if addresses:

            try:

                pairs = await get_data(
                    client,
                    "https://api.dexscreener.com/"
                    "tokens/v1/bsc/"
                    + ",".join(addresses)
                )

                best = {}

                for pair in pairs:

                    if pair.get("chainId") != "bsc":
                        continue

                    if "pancake" not in pair.get(
                        "dexId", ""
                    ).lower():
                        continue

                    address = pair.get(
                        "baseToken", {}
                    ).get("address", "").lower()

                    liquidity = number(
                        pair.get("liquidity", {}).get("usd")
                    )

                    if liquidity < MIN_LIQUIDITY:
                        continue

                    if address not in best or liquidity > number(
                        best[address].get(
                            "liquidity", {}
                        ).get("usd")
                    ):
                        best[address] = pair

                for address, pair in best.items():

                    security = await security_check(
                        client, address
                    )

                    analysis = analyze(
                        pair, security
                    )

                    items.append({
                        "name": pair.get(
                            "baseToken", {}
                        ).get("name"),

                        "symbol": pair.get(
                            "baseToken", {}
                        ).get("symbol"),

                        "address": address,

                        "liquidity": number(
                            pair.get(
                                "liquidity", {}
                            ).get("usd")
                        ),

                        "analysis": analysis,

                        "url": pair.get("url")
                    })

            except Exception as error:
                errors.append(str(error))

    items.sort(
        key=lambda x: x["analysis"]["score"],
        reverse=True
    )

    state["items"] = items
    state["updated"] = datetime.now(
        timezone.utc
    ).isoformat()

    state["errors"] = errors

    return {
        "items": items,
        "updated": state["updated"],
        "errors": errors,
        "mode": "PAPER ONLY"
    }


@app.get("/api/status")
async def status():

    return {
        "balance": 100,
        "max_daily_signals": MAX_SIGNALS,
        "network": "BNB Chain",
        "live_trading": False,
        "last_scan": state["updated"]
    }
