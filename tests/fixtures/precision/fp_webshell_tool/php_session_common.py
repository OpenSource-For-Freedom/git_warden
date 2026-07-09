"""Offensive-security tool (webshell manager) generating PHP payloads.

The tool's PURPOSE is to build `eval(base64_decode(...))` strings and send them to
a webshell it operates. The decode argument is a VARIABLE / f-string of a value the
tool encodes at runtime -- there is no embedded literal payload here.
"""

PAYLOAD_B64 = "..."  # supplied by the operator at runtime


def build_eval(code: str) -> str:
    return f"eval(base64_decode({base64_encode(code)!r}));"


def submit(code_b64):
    return eval(base64_decode(PAYLOAD_B64))  # tool sends this to its own session
