import re
import threading
import netifaces
import subprocess

from utils import *
from deadnet_apk import DeadNetAPK
from kivy.app import App
from kivymd.toast.kivytoast import toast
from kivymd.app import MDApp
from typing import Union

from kivy.clock import Clock

from jnius import autoclass
from scapy.all import *


class MainApp(MDApp):
    def __init__(self, **kwargs):
        # todo try build release
        # todo many prints for logcat... maybe debug button? (press refresh 7 times for debug mode?)

        # todo remove defined use a different format
        # TODO add versions to all requirements in specs
        # TODO remove not needed requiremenmts in specs
        self._GATEWAY_IPV4 = "undefined"
        self._GATEWAY_IPV6 = "undefined"
        self._GATEWAY_HWDDR = "undefined"
        self._IFACE = "undefined"
        self.ssid_name = "undefined"

        self._abort_lck = threading.RLock()
        self._deadnet_thread: Union[None, threading.Thread] = None
        self._deadnet_instance: Union[None, DeadNetAPK] = None

        self._root_status = False
        self._gateway_info = str()  # todo this can be instructions if nto set.. "try location, connect wifi"
        try:
            subprocess.call(["su"])  # test root
            self._root_status = True
        except (PermissionError, FileNotFoundError):
            pass

        super().__init__(**kwargs)

    def setup_network_data(self):
        with self._abort_lck:
            ctx = autoclass('android.content.Context')
            pa = autoclass('org.kivy.android.PythonActivity')
            wifi_service = pa.mActivity.getSystemService(ctx.WIFI_SERVICE)
            wifi_info = wifi_service.getConnectionInfo()
            ssid_name = wifi_info.getSSID().replace('"', '')
            if ssid_name == "<unknown ssid>":  # unable to get ssid
                ssid_name = f"{RED}Unable to detect an SSID (turn on location){COLOR_RESET}"
                self.clear_output_label()
            elif ssid_name == self.ssid_name:  # no change # TODO whats this
                pass
            else:  # new ssid
                # todo test for prints if bold even does any effect and remove if not
                self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR, self._IFACE = self.init_gateway()
                self._gateway_info = f"Net Interface - {BOLD}{self._IFACE}{COLOR_RESET}\n" \
                                     f"Gateway IPv4 - {BOLD}{self._GATEWAY_IPV4}{COLOR_RESET}\n" \
                                     f"Gateway IPv6 - {BOLD}{self._GATEWAY_IPV6}{COLOR_RESET}\n" \
                                     f"Gateway MACaddr - {BOLD}{self._GATEWAY_HWDDR}{COLOR_RESET}"
                # self.printf(gateway_info)
            self.set_ssid_name(ssid_name)  # todo handle if not found
            self.printf(self._gateway_info)

    def clear_output_label(self):
        try:
            self.printf("")  # clear output
        except Exception as exc:
            pass

    def set_ssid_name(self, ssid_name):
        try:
            self.root.ids.ssid_button.text = f"{YELLOW}{ssid_name}{COLOR_RESET}"
        except AttributeError:  # fails on startup - it's ok
            pass

    def init_gateway(self):
        # todo refactor get details methods to other place?
        gateway_ipv4 = gateway_ipv6 = iface = gateway_hwaddr = "undefined"

        try:
            # Step 1: Get the actual Wi-Fi interface name from getprop
            result = subprocess.run(['getprop'], capture_output=True, text=True)
            match = re.search(r'\[wifi.interface\]: \[(.*?)\]', result.stdout)
            if match:
                iface = match.group(1)
                print(f"@@@@@ iface: {iface}")

            # Step 2: Use Android APIs via pyjnius

            gateway_ipv4 = get_gateway_ipv4()
            print(f"@@@@@ Gateway IPv4 new method: {gateway_ipv4}")

            # Get  = gateway MAC address
            gateway_hwaddr = get_gateway_mac(iface)
            print(f"@@@@@ gateway_hwaddr: {gateway_hwaddr}")

            # Optional: Try IPv6 using /proc/net/if_inet6
            gateway_ipv6 = get_ipv6_with_su(iface)
            print(f"@@@@@ gateway_ipv6 (via su): {gateway_ipv6}")

        except Exception as exc:
            print(f"@@@@@ Error during init_gateway: {exc}")

        print(f"@@@@@ FINAL: {[gateway_ipv4, gateway_ipv6, gateway_hwaddr, iface]}")
        return gateway_ipv4, gateway_ipv6, gateway_hwaddr, iface

    def is_root(self):
        if not self._root_status:
            self.printf(f"{RED}device is not rooted!{COLOR_RESET}")
            return False
        return True

    def on_ref_credit_press(self, *args, **kwargs):
        import webbrowser # todo move up?
        webbrowser.open("https://github.com/flashnuke")

    def on_start_press(self):
        # todo: if not defined, then error msg box open
        # todo: brief popup window of "started"
        if self.is_root():
            self._toast_msg("Starting deadnet...")
            threading.Thread(target=self.do_attack, args=tuple()).start()

    def on_refresh_press(self):
        if self._is_deadnet_thread_active():
            self._toast_msg("Cannot refresh during attack")
        else:
            self._toast_msg("Refreshing gateway data...")
            self.setup_network_data()

    def do_attack(self):
        if self.is_root() and "<unknown ssid>" not in self.ssid_name:
            with self._abort_lck:
                if self._deadnet_instance:
                    return
                try:
                    self._deadnet_instance = DeadNetAPK(self._IFACE, self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR,
                                                   self.printf)
                except Exception as exc:
                    self.printf(f"error during setup -> {exc}")
                    return
            self._deadnet_thread = threading.Thread(target=self._deadnet_instance.start_attack, daemon=True)
            self._deadnet_thread.start()
            # todo: make t a variable that i can stop from elsewherw and wait to finish!@!

# todo wrapper for is_root for all buttons
# todo otherwise wrapper for is_connected_to_wifi to all buttons

    def on_stop_press(self):
        # todo: brief popup window of "stopped and errors"

        with self._abort_lck:
            if self._deadnet_instance:
                self._toast_msg("Stopping deadnet...")
                self._deadnet_instance.user_abort()
                if self._is_deadnet_thread_active():
                    self._deadnet_thread.join()
                self._toast_msg("Stopped deadnet")
                self._deadnet_instance = None  # todo make sure it's deleted
            else:
                self._toast_msg("Deadnet is not running")

    @staticmethod
    def _toast_msg(msg: str):
        toast(msg, duration=2, background=[0, 0, 0, 0.7])

    def _is_deadnet_thread_active(self):
        return self._deadnet_thread is not None and self._deadnet_thread.is_alive()

    def printf(self, text, fit_size=False):
        self.root.ids.output_label.text = text
        if fit_size:
            self.root.ids.output_label.text_size = self.root.ids.output_label.size

    def on_start(self):
        # on app start
        self.setup_network_data()


if __name__ == "__main__":
    app = MainApp()
    app.run()
