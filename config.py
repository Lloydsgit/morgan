Final config.py (with test + live support)
from config import get_next_wallet

config.py
MODE = "test" # Change to "live" when deploying live system

WALLET_POOL = {
"test": {
"TRC20": [
{
"address": "TXYx3NEThcWL2ZuhcgXu6mAqv5Lg6uFw5y",
"private_key": "62fc996e5e3e24f7d1998e476a77ef72c8b41cda0b8de36ef42f6a0cf44d7dce"
}
],
"ERC20": [
{
"address": 	"0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
"private_key": "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce03752e33ecb29d9a7fdd3"
}
]
},
"live": {
"TRC20": [
{
"address": "TXYx3NEThcWL2ZuhcgXu6mAqv5Lg6uFw5y",
"private_key": "62fc996e5e3e24f7d1998e476a77ef72c8b41cda0b8de36ef42f6a0cf44d7dce"
}
],
"ERC20": [
{
"address": "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
"private_key": "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce03752e33ecb29d9a7fdd3"
}
]
}
}

def get_next_wallet(currency, payout_type):
pool = WALLET_POOL[MODE].get(payout_type.upper(), [])
if not pool:
raise ValueError(f"No wallets found for {payout_type} in {MODE} mode.")
import random
return random.choice(pool)

Network endpoints
INFURA_URL = (
"https://goerli.infura.io/v3/YOUR_PROJECT_ID" if MODE == "test"
else "https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
)

TRONGRID_API_KEY = "your-trongrid-api-key" # Optional for live
