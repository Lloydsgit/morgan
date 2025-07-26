config.py (Round-Robin Version with test + live)

from itertools import cycle

MODE = "test" # Use "live" for production payouts

WALLET_POOL = {
"test": {
"TRC20": [
{
"address": "TXYx3NEThcWL2ZuhcgXu6mAqv5Lg6uFw5y",
"private_key": "62fc996e5e3e24f7d1998e476a77ef72c8b41cda0b8de36ef42f6a0cf44d7dce"
},
{
"address": "TXYx3NEThcWL2ZuhcgXu6mAqv5Lg6uFw5y",
"private_key": "62fc996e5e3e24f7d1998e476a77ef72c8b41cda0b8de36ef42f6a0cf44d7dce"
}
],
"ERC20": [
{
"address": "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
"private_key": "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce03752e33ecb29d9a7fdd3"
},
{
"address": "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
"private_key": "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce03752e33ecb29d9a7fdd3"
}
]
},
"live": {
"TRC20": [
{
"address": "TXYx3NEThcWL2ZuhcgXu6mAqv5Lg6uFw5y",
"private_key": "62fc996e5e3e24f7d1998e476a77ef72c8b41cda0b8de36ef42f6a0cf44d7dce"
},
}
],
"ERC20": [
{
"address": "0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
"private_key": "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce03752e33ecb29d9a7fdd3"
},
{

Create cyclers for round-robin selection
_wallet_cyclers = {
net: {
key: cycle(wallets)
for key, wallets in WALLET_POOL[net].items()
}
for net in WALLET_POOL
}

def get_next_wallet(currency, payout_type):
payout_type = payout_type.upper()
try:
return next(_wallet_cyclers[MODE][payout_type])
except KeyError:
raise ValueError(f"No wallets found for {payout_type} in {MODE} mode.")

INFURA_URL = (
"https://goerli.infura.io/v3/your-goerli-project-id" if MODE == "test"
else "https://mainnet.infura.io/v3/your-mainnet-project-id"
)

TRONGRID_API_KEY = "your-testnet-or-mainnet-trongrid-key"
