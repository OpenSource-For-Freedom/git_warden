# Backs up the user's own Electrum wallets to a local folder they choose.
import os
import shutil

SRC = os.path.join(os.path.expanduser("~"), ".electrum", "wallets")


def backup(dest):
    shutil.copytree(SRC, dest, dirs_exist_ok=True)
