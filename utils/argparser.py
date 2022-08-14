import argparse
import os

_DEF_CIDR = 24
_DEF_SLEEPTIME = 5
_DEF_PREFLEN = 64


def define_args():
    parser = argparse.ArgumentParser(description=f'Perform an ARP cache poison attack',
                                     usage=f"./{os.path.basename(__file__)} iface")
    parser.add_argument("-i", "--network-interface", dest='iface', type=str, metavar=(""),
                        help="the name of the network interface (from `ifconfig`, i.e -> 'eth0')",
                        required=True)

    parser.add_argument("-m", "--set-cidrlen", dest='cidrlen', type=int, metavar=(""), default=_DEF_CIDR,
                        help=f"set the IPv4 subnet cidr length (default -> /{_DEF_CIDR}",
                        required=False)

    parser.add_argument("-s", "--sleep-interval", dest='s_time', type=int, metavar=(""), default=_DEF_SLEEPTIME,
                        help=f"set the sleep time between each arp poison attempt (default -> {_DEF_SLEEPTIME}[sec])",
                        required=False)

    parser.add_argument("-g", "--set-gateway", dest='gateway', type=str, metavar=(""), default=None,
                        help="set the gateway ip manually (defaults to x.x.x.1)",
                        required=False)

    parser.add_argument("-6", "--spoof_ipv6ra", dest='spoof_ipv6ra', action="store_true",
                        default=False, help="spoof IPv6 ra packets, causing a dead router attack"
                                            " (disabled by default)", required=False)

    parser.add_argument("-pl", "--set-preflen", dest='preflen', type=int, metavar=(""), default=_DEF_PREFLEN,
                        help=f"set the prefix length of the IPv6 subnet (default -> {_DEF_PREFLEN})",
                        required=False)

    return parser.parse_args()
