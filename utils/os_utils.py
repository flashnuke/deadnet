import sys
import time


def get_ts_ms():
    return int(time.time() * 1_000)


def os_is_linux():
    return "linux" in sys.platform


def os_is_windows():
    return sys.platform.startswith('win')
