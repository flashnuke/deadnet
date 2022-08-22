import os
import sys

_DEVNULL = open(os.devnull, "w")
_ORIG_STDOUT = sys.stdout


def _invalidate_print():
    global _DEVNULL
    sys.stdout = _DEVNULL


def printf(text):
    global _ORIG_STDOUT, _DEVNULL
    sys.stdout = _ORIG_STDOUT
    print(text)
    sys.stdout = _DEVNULL
