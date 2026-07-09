"""Legit devops: build a python one-liner to run a migration on a remote VM.

The decode target is a VARIABLE placeholder (`{encoded}`), not an embedded blob --
the payload is supplied at runtime, this is just command construction. Ubiquitous
in deployment tooling; not a hidden stager.
"""


def remote_python(encoded: str) -> str:
    return f"import base64; exec(base64.b64decode('{encoded}').decode('utf-8'))"


def apply_migration(encoded: str) -> list[str]:
    return ["ssh", "vm-host", "python3", "-c", remote_python(encoded)]
