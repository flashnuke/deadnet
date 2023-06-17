import re
import threading
import netifaces
import subprocess

from utils import *
from deadnet_apk import DeadNetAPK
from kivy.app import App
from jnius import autoclass


class MainApp(App):
    def __init__(self, **kwargs):
        self._GATEWAY_IPV4 = "undefined"
        self._GATEWAY_IPV6 = "undefined"
        self._GATEWAY_HWDDR = "undefined"
        self._IFACE = "undefined"
        self.ssid_name = "undefined"

        self._abort_lck = threading.RLock()
        self.setup_network_data()
        self._deadnet_ins = None

        self._root_status = False
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
                ssid_name = f"{RED}Unable to detect an SSID{COLOR_RESET}"
                self.clear_output_label()
            elif ssid_name == self.ssid_name:  # no change
                pass
            else:  # new ssid
                self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR, self._IFACE = self.init_gateway()
                self.clear_output_label()
            self.ssid_name = ssid_name
            self.set_ssid_name()

    def clear_output_label(self):
        try:
            self.printf("")  # clear output
        except Exception as exc:
            pass

    def set_ssid_name(self):
        try:
            self.root.ids.ssid_button.text = f"{YELLOW}{self.ssid_name}{COLOR_RESET}"
        except AttributeError:  # fails on startup - it's ok
            pass

    @staticmethod
    def init_gateway():
        gateway_ipv4, gateway_ipv6, iface, gateway_hwaddr = "undefined", "undefined", "undefined", "undefined"
        try:
            gateways = netifaces.gateways()
            ipv4_data = gateways[netifaces.AF_INET][0]  # take first for IPv4
            gateway_ipv4 = ipv4_data[0]
            iface = ipv4_data[1]

            ipv6_data = gateways.get(netifaces.AF_INET6, list())
            for d in ipv6_data:
                if d[1] == iface:
                    gateway_ipv6 = d[0]

            result = subprocess.run(['ip', 'neighbor', 'show', 'default'], capture_output=True, text=True)
            output = result.stdout.strip()

            for line in output.split('\n'):
                columns = line.split()
                if len(columns) >= 4:
                    if columns[3] == 'lladdr' and columns[4] != '<incomplete>' and columns[2] == iface:
                        gateway_hwaddr = columns[4]
                        break
        except Exception as exc:
            pass

        return gateway_ipv4, gateway_ipv6, gateway_hwaddr, iface

    def is_root(self):
        if not self._root_status:
            self.printf(f"{RED}device is not rooted!{COLOR_RESET}")
            return False
        return True

    def on_ref_credit_press(self, *args, **kwargs):
        import webbrowser
        webbrowser.open("https://github.com/flashnuke")

    def on_start_press(self):
        if self.is_root():
            threading.Thread(target=self.do_attack, args=tuple()).start()

    def do_attack(self):
        if self.is_root() and "<unknown ssid>" not in self.ssid_name:
            with self._abort_lck:
                if self._deadnet_ins:
                    return
                try:
                    self._deadnet_ins = DeadNetAPK(self._IFACE, self._GATEWAY_IPV4, self._GATEWAY_IPV6, self._GATEWAY_HWDDR,
                                                   self.printf)
                except Exception as exc:
                    self.printf(f"error during setup -> {exc}")
                    return
            self._deadnet_ins.start_attack()

    def on_stop_press(self):
        with self._abort_lck:
            if self._deadnet_ins:
                self._deadnet_ins.user_abort()
            self._deadnet_ins = None

    def printf(self, text, fit_size=False):
        self.root.ids.output_label.text = text
        if fit_size:
            self.root.ids.output_label.text_size = self.root.ids.output_label.size


if __name__ == "__main__":
    app = MainApp()
    app.run()
