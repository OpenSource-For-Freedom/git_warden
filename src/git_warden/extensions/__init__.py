"""VS Code extension hunting (Open VSX).

Tier 1 screens registry metadata on the host (cheap, no extension bytes are
fetched). Tier 2 downloads and statically analyzes the ``.vsix`` inside the
hardened sandbox container, so an extension's code never touches the host.
"""
