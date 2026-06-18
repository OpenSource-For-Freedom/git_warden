#!/usr/bin/env python
"""Run Git Warden without installing it.

    python gw.py probe --feed osm --ecosystem npm
    python gw.py ingest

Puts ``src`` on the import path and dispatches to the CLI, so no editable
install or PYTHONPATH juggling is needed. Credentials load from .env (see
.env.example).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from git_warden.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
