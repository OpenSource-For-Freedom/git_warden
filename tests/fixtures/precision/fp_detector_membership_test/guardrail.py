# From cataclypsme/ai-engineering-from-scratch, an AI-engineering COURSE that
# confirmed AUTO on the 2026-08-07 sweep via steal-and-send (keyfiles + paste-exfil
# in one file). Both are teaching/defensive constructs, not an attack:
#  - the credential path is a tutorial Action example, data not a read
#  - the webhook.site reference is a GUARDRAIL that DETECTS exfiltration attempts
# A line that tests FOR an indicator is a detector, the same idea as an inline
# regexp rule table, so neither should confirm the repo malicious.
from framework import Action

DEMO_ACTIONS = [
    Action("read", "~/.aws/credentials"),   # tutorial example of a sensitive read
    Action("write", "/tmp/output.txt"),
]


def is_dangerous(payload: str) -> bool:
    """Guardrail: flag a payload that looks like exfiltration or remote exec."""
    if "curl " in payload and ("attacker" in payload or "paste" in payload
                               or "webhook.site" in payload):
        return True
    if payload.includes("pastebin.com/api"):
        return True
    return False
