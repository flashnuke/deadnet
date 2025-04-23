import re
import threading
import netifaces
import subprocess
import socket
import struct # TODO check if all imports are needed BUT DO NOT REMOVE SOME THAT ARE NEEDED BUT CAN BE RUN WITHOUT

from utils import *
from deadnet_apk import DeadNetAPK
from kivy.app import App
from kivymd.toast.kivytoast import toast
from kivymd.app import MDApp


from kivy.clock import Clock

from jnius import autoclass
from scapy.all import *

class MainApp(MDApp):
    def __init__(self, **kwargs):
        # todo try build release
        # todo force bg to be dark theme

        # todo remove defined use a different format
        # TODO add versions to all requirements in specs
        # TODO remove not needed requiremenmts in specs
        self._GATEWAY_IPV4 = "undefined"
        self._GATEWAY_IPV6 = "undefined"
        self._GATEWAY_HWDDR = "undefined"
        self._IFACE = "undefined"
        self.ssid_name = "undefined"

        self._abort_lck = threading.RLock()
        self._deadnet_ins = None

        self._root_status = False
        self._gateway_info = str() # todo this can be instructions if nto set.. "try location, connect wifi"
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

    @staticmethod
    def get_ipv6_with_su(iface):
        try:
            su_cmd = f"cat /proc/net/if_inet6"
            result = subprocess.run(['su', '-c', su_cmd], capture_output=True, text=True)

            if result.returncode != 0:
                print(f"@@@@@ su command failed: {result.stderr.strip()}")
                return "undefined"

            for line in result.stdout.strip().splitlines():
                parts = line.strip().split()
                if parts[-1] == iface:
                    raw = parts[0]
                    ipv6 = ':'.join([raw[i:i + 4] for i in range(0, len(raw), 4)])
                    return ipv6
        except Exception as e:
            print(f"@@@@@ Exception in get_ipv6_with_su: {e}")
        return "undefined"

    @staticmethod
    def get_gateway_ip():
        # grab the Android activity and Wi‑Fi service
        PythonActivity = autoclass('org.kivy.android.PythonActivity')
        activity = PythonActivity.mActivity
        Context = autoclass('android.content.Context')
        wifi_service = activity.getSystemService(Context.WIFI_SERVICE)

        # get the DhcpInfo and pull out the gateway int
        dhcp_info = wifi_service.getDhcpInfo()
        gw_int = dhcp_info.gateway

        # convert little‑endian int to dotted quad
        gw_ip = "{}.{}.{}.{}".format(
            gw_int & 0xFF,
            (gw_int >> 8) & 0xFF,
            (gw_int >> 16) & 0xFF,
            (gw_int >> 24) & 0xFF
        )

        return gw_ip

    @staticmethod
    def get_gateway_mac(iface):
        try:
            # build the su command
            cmd = 'ip neighbor show default'
            # run it as root
            result = subprocess.run(
                ['su', '-c', cmd],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()
            print(f"@@@@@ output: {output}")

            # parse each line for "lladdr" on our interface
            for line in output.splitlines():
                cols = line.split()
                # example cols: ['192.168.1.1', 'dev', 'wlan0', 'lladdr', 'aa:bb:cc:dd:ee:ff', 'REACHABLE']
                if len(cols) >= 5 and cols[3] == 'lladdr' and cols[4] != '<incomplete>':
                    if cols[2] == iface:
                        return cols[4]
        except subprocess.CalledProcessError as e:
            # ip/ su failed
            print(f"@@@@@ Error running ip neighbor: {e}")
        except Exception as exc:
            # something else went wrong
            print(f"@@@@@ Unexpected error: {exc}")
        return None

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

            gateway_ipv4 = self.get_gateway_ip()
            print(f"@@@@@ Gateway IPv4 new method: {gateway_ipv4}")

            # Get  = gateway MAC address
            gateway_hwaddr = self.get_gateway_mac(iface)
            print(f"@@@@@ gateway_hwaddr: {gateway_hwaddr}")

            # Optional: Try IPv6 using /proc/net/if_inet6
            gateway_ipv6 = self.get_ipv6_with_su(iface)
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
            threading.Thread(target=self.do_attack, args=tuple()).start()

    def on_refresh_press(self):
        # todo: cant hit refresh while attacking.
        # todo: brief popup window of that error
        self.setup_network_data()

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
            t = threading.Thread(target=self._deadnet_ins.start_attack, daemon=True)
            t.start()
            # todo: make t a variable that i can stop from elsewherw and wait to finish!@!


    def on_stop_press(self):
        # todo: brief popup window of "stopped and errors"

        with self._abort_lck:
            if self._deadnet_ins:
                self._deadnet_ins.user_abort()
            self._deadnet_ins = None  # todo make sure it's deleted

        # TODO TAKE THIS FOR MSGING
        toast(
            "Invalid action",
            duration=1.5,
            background=[0, 0, 0, 0.7]
        )

    def printf(self, text, fit_size=False):
        self.root.ids.output_label.text = text
        if fit_size:
            self.root.ids.output_label.text_size = self.root.ids.output_label.size

    def on_start(self):
        # on app start
        self.toast_container = self.root # todo define in constructor
        self.setup_network_data()  # TODO refactor into a reset button


if __name__ == "__main__":
    app = MainApp()
    app.run()
