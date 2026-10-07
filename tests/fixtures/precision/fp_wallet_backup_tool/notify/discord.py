# Posts "backup finished" to the user's own Discord channel.
import requests

HOOK = "https://discord.com/api/webhooks/000000000000000000/fixture-token"


def done():
    requests.post(HOOK, json={"content": "backup finished"})
