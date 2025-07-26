Final config.py (with test + live support)

config.py
MODE = "test" # Change to "live" when deploying live system

WALLET_POOL = {
"test": {
"TRC20": [
{
"address": "TMnHdKzr6zciwYQVDuRn1k8aQ2HdWyhVzQ",
"private_key": "a1b2c3d4e5f6g7h8i9j0dummytestkey123"
}
],
"ERC20": [
{
"address": "0x1E0049783F008A0085193E00003D00cd54003c71",
"private_key": "0xabcde12345678900deadbeef00feedface0011223344"
}
]
},
"live": {
"TRC20": [
{
"address": "TLiveWalletAddressHere",
"private_key": "LiveWalletPrivateKeyHere"
}
],
"ERC20": [
{
"address": "0xLiveMainnetAddressHere",
"private_key": "LiveMainnetPrivateKeyHere"
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
