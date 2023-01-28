import sys
import time


def get_ts_ms():
    return int(time.time() * 1_000)


def mac2ipv6_ll(mac, pref):
    m = hex(int(mac.translate(str.maketrans('', '', ' .:-')), 16) ^ 0x020000000000)[2:]
    return f'{pref}::%s:%sff:fe%s:%s' % (m[:4], m[4:6], m[6:8], m[8:12])


def os_is_linux():
    return "linux" in sys.platform


def os_is_windows():
    return sys.platform.startswith('win')
