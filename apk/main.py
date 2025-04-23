import re
import threading
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

# todo note: pc - use bridged not nat, executor, more stable to get gateway, python interpretr no permissiosn therefore C++... etc...
class MainApp(MDApp):
    UNDEFINED_NICK = "null"
    def __init__(self, **kwargs):
        # todo init gateway clean up
        # todo test on unrooted phone
        # todo try build release
        # todo many prints for logcat... maybe debug button? (press refresh 7 times for debug mode?)
        # todo verify sudo for main pc also
        # todo maybe if clicking on gateway status u can set custom gateway data?

        # todo remove defined use a different format
        # TODO add versions to all requirements in specs
        # TODO remove not needed requiremenmts in specs

        # TODO test regular deadnet again
        self._GATEWAY_IPV4 = self._GATEWAY_IPV6 = self._GATEWAY_HWDDR = self._IFACE = self.ssid_name = \
            MainApp.UNDEFINED_NICK

        self._abort_lck = threading.RLock()
        self._deadnet_thread: Union[None, threading.Thread] = None
        self._deadnet_instance: Union[None, DeadNetAPK] = None

        self._root_status = self._try_root()

        super().__init__(**kwargs)

    @staticmethod
    def _try_root():
        try:
            subprocess.call(["su"])  # test root
            return True
        except (PermissionError, FileNotFoundError):  # todo print exc for logcat
            pass
        return False

    def _check_app_conditions(self, check_root: bool, check_ssid: bool):
        if check_root and not self._has_root_status():
            self._toast_msg("Error: device is not rooted")
        elif check_ssid and not self._has_ssid():
            self._toast_msg("Error: no wifi connection was found")
        else:
            return True
        return False

    def setup_network_data(self):
        with self._abort_lck:
            ssid_name = get_ssid_name()
            self.set_ssid_name(ssid_name)  # todo handle if not found

            if not self._has_ssid():  # unable to get ssid
                setup_output = f"{RED}Error{COLOR_RESET}: Unable to detect an SSID" \
                               f"\nPlease make sure of the following:" \
                               f"{BLUE}*{COLOR_RESET} Device is connected to wifi" \
                               f"{BLUE}*{COLOR_RESET} Location is enabled" \
                               f"{BLUE}*{COLOR_RESET} Location permission is granted"
                # todo (turn on location) otherwise print info otherwise...
            else:  # has ssid
                # todo test for prints if bold even does any effect and remove if not
                self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR, self._IFACE = init_gateway()
                setup_output = f"Net Interface - {BOLD}{self._IFACE}{COLOR_RESET}\n" \
                               f"Gateway IPv4 - {BOLD}{self._GATEWAY_IPV4}{COLOR_RESET}\n" \
                               f"Gateway IPv6 - {BOLD}{self._GATEWAY_IPV6}{COLOR_RESET}\n" \
                               f"Gateway MACaddr - {BOLD}{self._GATEWAY_HWDDR}{COLOR_RESET}"
            self.printf(setup_output)

    def clear_output_label(self):
        try:
            self.printf("")  # clear output
        except Exception as exc:
            pass

    def set_ssid_name(self, ssid_name):
        self.ssid_name = ssid_name
        try:
            self.root.ids.ssid_label.text = f"{YELLOW}{self.ssid_name}{COLOR_RESET}"
        except AttributeError:  # fails on startup - it's ok
            pass

    def _has_ssid(self):
        return not is_unknown_ssid(self.ssid_name)  # todo and not "undefined"

    def _has_root_status(self): # todo remove?
        return self._root_status
            # self.printf(f"{RED}device is not rooted!{COLOR_RESET}")
            # return False
        # return True

    def on_ref_credit_press(self, *args, **kwargs):
        try:
            import webbrowser # todo move up?
            webbrowser.open("https://github.com/flashnuke")
        except Exception as exc:
            print("print exc here") # todo print to logcat

    def on_start_press(self):
        if not self._check_app_conditions(check_root=True, check_ssid=True):
            return
        if self._is_deadnet_thread_active():
            self._toast_msg("Already running")
        else:
            self._toast_msg("Starting deadnet...")
            threading.Thread(target=self.do_attack, args=tuple()).start()

    def on_refresh_press(self):
        if not self._check_app_conditions(check_root=True, check_ssid=False):
            return
        if self._is_deadnet_thread_active():
            self._toast_msg("Cannot refresh during attack")
        else:
            self._toast_msg("Refreshing gateway data...")
            self.setup_network_data()

    def do_attack(self):
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

    def on_stop_press(self):
        if not self._check_app_conditions(check_root=True, check_ssid=True):
            return
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
        if not self._check_app_conditions(check_root=True, check_ssid=False):
            err_msg = f"{RED}Error{COLOR_RESET}: Device is not rooted!"
            self.printf(err_msg)
        else:
            self.setup_network_data()


if __name__ == "__main__":
    app = MainApp()
    app.run()
