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
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.core.clipboard import Clipboard
from kivy.uix.scrollview import ScrollView
from kivy.metrics import dp

# from kivymd.uix.snackbar import MDSnackbar


from kivy.clock import Clock
from kivy.logger import Logger, LoggerHistory, LOG_LEVELS

from jnius import autoclass

Logger.setLevel(LOG_LEVELS["info"])


# todo note: pc - use bridged not nat, executor, more stable to get gateway, python interpretr no permissiosn therefore C++... etc...
class MainApp(MDApp):
    GH_URL = "https://github.com/flashnuke"

    def __init__(self, **kwargs):
        # todo test functionality after removign scapy / RandMAC
        # todo test on unrooted phone
        # todo try build release

        self._GATEWAY_IPV4 = self._GATEWAY_IPV6 = self._GATEWAY_HWDDR = self._IFACE = self.ssid_name = \
            NET_UNDEFINED

        self._abort_lck = threading.RLock()
        self._deadnet_thread: Union[None, threading.Thread] = None
        self._deadnet_instance: Union[None, DeadNetAPK] = None

        self._root_status = self._try_root()

        super().__init__(**kwargs)

    @staticmethod
    def _try_root() -> bool:
        try:
            subprocess.call(["su"])  # test root
            return True
        except (PermissionError, FileNotFoundError):
            Logger.error(f"DeadNet: _try_root missing root")
            pass
        except Exception as e:
            Logger.error(f"DeadNet: _try_root exception {e} traceback {traceback.format_exc()}")
        return False

    def _check_app_conditions(self, check_root: bool, check_ssid: bool) -> bool:
        if check_root and not self._has_root_status():
            self._toast_msg("Error: Device is not rooted")
        elif check_ssid and not self._has_ssid():
            self._toast_msg("Error: No wifi connection was found")
        else:
            return True
        return False

    def setup_network_data(self) -> None:
        with self._abort_lck:
            ssid_name = get_ssid_name()
            self.set_ssid_name(ssid_name)

            if not self._has_ssid():  # unable to get ssid
                setup_output = f"Unable to detect a wifi connection\n" \
                               f"Please make sure of the following:\n\n" \
                               f"    {BLUE}*{COLOR_RESET}    Device is connected to wifi\n" \
                               f"    {BLUE}*{COLOR_RESET}    Location is enabled\n" \
                               f"    {BLUE}*{COLOR_RESET}    Location permission is granted"
            else:  # has ssid
                self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR, self._IFACE = init_gateway()
                setup_output = f"Net Interface    -    {self._IFACE}\n" \
                               f"Gateway IPv4    -    {self._GATEWAY_IPV4}\n" \
                               f"Gateway IPv6    -    {self._GATEWAY_IPV6}\n" \
                               f"Gateway MACaddr    -    {self._GATEWAY_HWDDR}"
            self.printf(setup_output)

    def set_ssid_name(self, ssid_name: str) -> None:
        self.ssid_name = ssid_name
        self.root.ids.ssid_label.text = f"{YELLOW}{self.ssid_name}{COLOR_RESET}"

    def _has_ssid(self) -> bool:
        return not is_unknown_ssid(self.ssid_name) and self.ssid_name != NET_UNDEFINED

    def _has_root_status(self) -> bool:
        return self._root_status

    def on_ref_credit_press(self) -> None:
        try:
            import webbrowser
            webbrowser.open(self.GH_URL)
        except Exception as e:
            Logger.error(f"DeadNet: on_ref_credit_press exception {e} when opening {self.GH_URL} traceback {traceback.format_exc()}")

    def on_start_press(self) -> None:
        if not self._check_app_conditions(check_root=True, check_ssid=True):
            return
        if self._is_deadnet_thread_active():
            self._toast_msg("Already running")
        else:
            self._toast_msg("Starting deadnet...")
            threading.Thread(target=self.do_attack, args=tuple()).start()

    def on_refresh_press(self) -> None:
        if not self._check_app_conditions(check_root=True, check_ssid=False):
            return
        if self._is_deadnet_thread_active():
            self._toast_msg("Cannot refresh during attack")
        else:
            self._toast_msg("Refreshing gateway data...")
            self.setup_network_data()

    def on_stop_press(self) -> None:
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

    def on_debug_press(self) -> None:
        try:
            # Step 1: Get log messages
            history = [record.msg for record in LoggerHistory.history if "DeadNet:" in record.msg]
            debug_text = "\n============\n".join(history)
            print(debug_text)

            box = BoxLayout(orientation='vertical', padding=20, spacing=20)

            label = Label(
                text=debug_text or "[no debug logs found]",
                font_size=20,
                color=(1, 1, 1, 1),
                halign='left',
                valign='top',
                size_hint_y=None,
                text_size=(self.root.width * 0.8, None)
            )
            label.bind(texture_size=label.setter('size'))

            scroll = ScrollView(size_hint=(1, 1))
            scroll.add_widget(label)
            box.add_widget(scroll)

            btn_row = BoxLayout(size_hint=(1, 0.2), spacing=10)

            copy_btn = Button(
                text='Copy',
                size_hint=(0.5, 0.75),
                background_color=(0.2, 0.2, 0.2, 1),
                font_size=30,
                color=(1, 1, 1, 1)
            )
            copy_btn.bind(on_press=lambda *a: self._copy_to_clipboard(debug_text))

            close_btn = Button(
                text='Close',
                size_hint=(0.5, 0.75),
                background_color=(0.2, 0.2, 0.2, 1),
                font_size=30,
                color=(1, 1, 1, 1)
            )
            popup = Popup(
                title='Debug logs',
                content=box,
                size_hint=(0.9, 0.8),
                auto_dismiss=False,
                background_color=(0.1, 0.1, 0.1, 0.95)
            )
            close_btn.bind(on_press=lambda *a: popup.dismiss())

            btn_row.add_widget(copy_btn)
            btn_row.add_widget(close_btn)
            box.add_widget(btn_row)

            popup.open()

        except Exception as e:
            Logger.error(f"DeadNet: on_debug_press failed - {e}, traceback {traceback.format_exc()}")

    def do_attack(self) -> None:
        with self._abort_lck:
            if self._deadnet_instance:
                return
            try:
                self._deadnet_instance = DeadNetAPK(self._IFACE,
                                                    self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR,
                                                    self.printf)
            except Exception as e:
                Logger.error(f"DeadNet: Exception {e} when starting attack, traceback: {traceback.format_exc()}")
                self.printf(f"error during setup -> {e}")
                return
        self._deadnet_thread = threading.Thread(target=self._deadnet_instance.start_attack, daemon=True)
        self._deadnet_thread.start()

    def _copy_to_clipboard(self, text: str) -> None:
        Clipboard.copy(text)
        self._toast_msg("Copied to clipboard")

    @staticmethod
    def _toast_msg(msg: str) -> None:
        print("called toast")
        # MDSnackbar(
        #     text=msg,
        #     md_bg_color=(0, 0, 0, 0.8),
        #     duration=2,
        #     y=dp(10),  # vertical offset
        #     pos_hint={"center_x": 0.5},  # now honored!
        #     size_hint_x=0.9,  # 90% width
        # ).open()
        # toast(msg, duration=2, background=[0, 0, 0, 0.7])  # todo check if neede to revert to 0.7

    def _is_deadnet_thread_active(self) -> bool:
        return self._deadnet_thread is not None and self._deadnet_thread.is_alive()

    def printf(self, text, fit_size=False):
        self.root.ids.output_label.text = text
        if fit_size:
            self.root.ids.output_label.text_size = self.root.ids.output_label.size

    def on_start(self) -> None:
        # on app start
        if not self._check_app_conditions(check_root=True, check_ssid=False):
            err_msg = f"{RED}Error{COLOR_RESET}: Device is not rooted!"
            self.printf(err_msg)
        else:
            self.setup_network_data()


if __name__ == "__main__":
    app = MainApp()
    app.run()
