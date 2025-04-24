import re
import threading
import subprocess
import traceback

from utils import *
from deadnet_apk import DeadNetAPK
from kivy.app import App
from kivymd.toast.kivytoast import toast
from kivymd.app import MDApp
from typing import Union

from kivy.clock import Clock
from kivy.logger import Logger, LoggerHistory

from jnius import autoclass
from scapy.all import *


# todo note: pc - use bridged not nat, executor, more stable to get gateway, python interpretr no permissiosn therefore C++... etc...
class MainApp(MDApp):
    GH_URL = "https://github.com/flashnuke"

    def __init__(self, **kwargs):
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
            NET_UNDEFINED

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
        except (PermissionError, FileNotFoundError):
            Logger.error(f"DeadNet: _try_root missing root")
            pass
        except Exception as e:
            Logger.error(f"DeadNet: _try_root exception {e} traceback {traceback.format_exc()}")
        return False

    def _check_app_conditions(self, check_root: bool, check_ssid: bool):
        if check_root and not self._has_root_status():
            self._toast_msg("Error: Device is not rooted")
        elif check_ssid and not self._has_ssid():
            self._toast_msg("Error: No wifi connection was found")
        else:
            return True
        return False

    def setup_network_data(self):
        with self._abort_lck:
            ssid_name = get_ssid_name()
            self.set_ssid_name(ssid_name)

            if not self._has_ssid():  # unable to get ssid
                setup_output = f"Unable to detect a wifi connection\n" \
                               f"Please make sure of the following:\n\n" \
                               f"   {BLUE}*{COLOR_RESET} Device is connected to wifi\n" \
                               f"   {BLUE}*{COLOR_RESET} Location is enabled\n" \
                               f"   {BLUE}*{COLOR_RESET} Location permission is granted"
            else:  # has ssid
                self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR, self._IFACE = init_gateway()
                setup_output = f"Net Interface - {self._IFACE}\n" \
                               f"Gateway IPv4 - {self._GATEWAY_IPV4}\n" \
                               f"Gateway IPv6 - {self._GATEWAY_IPV6}\n" \
                               f"Gateway MACaddr - {self._GATEWAY_HWDDR}"
            self.printf(setup_output)

    def clear_output_label(self):
        self.printf("")  # clear output

    def set_ssid_name(self, ssid_name):
        self.root.ids.ssid_label.text = f"{YELLOW}{self.ssid_name}{COLOR_RESET}"

    def _has_ssid(self):
        return not is_unknown_ssid(self.ssid_name) and self.ssid_name != NET_UNDEFINED

    def _has_root_status(self):
        return self._root_status

    def on_ref_credit_press(self):
        try:
            import webbrowser
            webbrowser.open(self.GH_URL)
        except Exception as e:
            Logger.error(f"DeadNet: on_ref_credit_press exception {e} when opening {self.GH_URL} traceback {traceback.format_exc()}")

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
            except Exception as e:
                Logger.error(f"DeadNet: Exception {e} when starting attack, traceback: {traceback.format_exc()}")
                self.printf(f"error during setup -> {e}")
                return
        self._deadnet_thread = threading.Thread(target=self._deadnet_instance.start_attack, daemon=True)
        self._deadnet_thread.start()

    def on_stop_press(self):
        Logger.info(f"historyyy: {LoggerHistory.history}")
        Logger.error(f"testttt")
        if not self._check_app_conditions(check_root=True, check_ssid=True):
            return

        with self._abort_lck:
            if self._deadnet_instance:
                self._toast_msg("Stopping deadnet...")
                self._deadnet_instance.user_abort()
                if self._is_deadnet_thread_active():
                    self._deadnet_thread.join()
                self._toast_msg("Stopped deadnet")
                self._deadnet_instance = None
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
