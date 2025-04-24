import re
import random
import ipaddress
import traceback
import subprocess

from typing import Tuple
from jnius import autoclass
from kivy.logger import Logger

NET_UNDEFINED = "null"


def is_unknown_ssid(ssid: str) -> bool:
    if not ssid:
        return True
    ssid_clean = ssid.strip().lower().replace('"', '')
    return ssid_clean == '<unknown ssid>'


def get_device_mac_address_su(iface: str) -> str:
    try:
        result = subprocess.run(['su', '-c', f'cat /sys/class/net/{iface}/address'], capture_output=True, text=True)
        Logger.info(f"DeadNet: get_device_mac_address_su cmd result - {result}")
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        Logger.error(f"DeadNet: get_device_mac_address_su error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


def get_if_addr(iface: str) -> str:
    result = subprocess.run(['su', '-c', f'ip -4 addr show dev {iface}'],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
    if match:
        return match.group(1)
    else:
        Logger.error(f"DeadNet: get_if_addr cmd missing match, result - {result}")
    return NET_UNDEFINED


def get_ssid_name() -> str:
    ssid_name = NET_UNDEFINED
    try:
        ctx = autoclass('android.content.Context')
        pa = autoclass('org.kivy.android.PythonActivity')
        wifi_service = pa.mActivity.getSystemService(ctx.WIFI_SERVICE)
        wifi_info = wifi_service.getConnectionInfo()
        ssid_name = wifi_info.getSSID().replace('"', '')
    except Exception as e:
        Logger.error(f"DeadNet: get_ssid_name error {e} - {traceback.format_exc()}")
    return ssid_name


def get_net_iface_name() -> str:
    try:
        result = subprocess.run(['getprop'], capture_output=True, text=True)
        match = re.search(r'\[wifi.interface\]: \[(.*?)\]', result.stdout)
        if match:
            Logger.info(f"DeadNet: get_net_iface_name cmd result success")  # avoid printing if match - too much spam
            return match.group(1)
        else:
            Logger.error(f"DeadNet: get_net_iface_name cmd missing match, result - {result}")
    except Exception as e:
        Logger.error(f"DeadNet: get_net_iface_name error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


def get_ipv6_with_su(iface: str) -> str:
    try:
        su_cmd = f"cat /proc/net/if_inet6"
        result = subprocess.run(['su', '-c', su_cmd], capture_output=True, text=True)
        Logger.info(f"DeadNet: get_ipv6_with_su cmd result - {result}")
        for line in result.stdout.strip().splitlines():
            parts = line.strip().split()
            if parts[-1] == iface:
                raw = parts[0]
                ipv6 = ':'.join([raw[i:i + 4] for i in range(0, len(raw), 4)])
                return ipv6
    except Exception as e:
        Logger.error(f"DeadNet: get_ipv6_with_su error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


def get_ipv6_gateway_via_proc_su(iface: str) -> str:
    try:
        result = subprocess.run(['su', '-c', 'cat /proc/net/ipv6_route'],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 7:
                continue
            dest, dest_pref, _, _, gateway_hex, _, route_iface = parts[:7]
            if dest == '0' * 32 and dest_pref == '00' and route_iface == iface:
                try:
                    gw_addr = str(ipaddress.IPv6Address(gateway_hex.zfill(32)))
                    return gw_addr
                except ipaddress.AddressValueError:
                    return None
    except Exception as e:
        Logger.error(f"DeadNet: get_gateway_ipv4 error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


# usage
def get_gateway_ipv4() -> str:
    try:
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
    except Exception as e:
        Logger.error(f"DeadNet: get_gateway_ipv4 error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


def get_gateway_mac(iface: str) -> str:
    try:
        cmd = 'ip neighbor show default'
        result = subprocess.run(['su', '-c', cmd], capture_output=True, text=True, check=True)
        Logger.info(f"DeadNet: get_gateway_mac cmd result - {result}")
        output = result.stdout.strip()
        # parse each line for "lladdr" on our interface
        for line in output.splitlines():
            cols = line.split()
            # example cols: ['192.168.1.1', 'dev', 'wlan0', 'lladdr', 'aa:bb:cc:dd:ee:ff', 'REACHABLE']
            if len(cols) >= 5 and cols[3] == 'lladdr' and cols[4] != '<incomplete>':
                if cols[2] == iface:
                    return cols[4]
    except Exception as e:
        Logger.error(f"DeadNet: get_gateway_mac error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


def init_gateway() -> Tuple[str, str, str, str]:
    gateway_ipv4 = gateway_ipv6 = iface = gateway_hwaddr = NET_UNDEFINED

    try:
        iface = get_net_iface_name()
        if is_unknown_ssid(iface):
            raise Exception("unable to get iface_name")
        gateway_ipv4 = get_gateway_ipv4()
        gateway_hwaddr = get_gateway_mac(iface)
        gateway_ipv6 = get_ipv6_gateway_via_proc_su(iface)
    except Exception as e:
        Logger.error(f"DeadNet: init_gateway error {e} - {traceback.format_exc()}")

    Logger.info(f"DeadNet: init_gateway success - {gateway_ipv4} {gateway_ipv6} {gateway_hwaddr} {iface}")
    return gateway_ipv4, gateway_ipv6, gateway_hwaddr, iface


def get_ipv6_prefdata(interface_name: str) -> Tuple[str, int]:
    prefix = ""
    preflen = 0
    try:
        result = subprocess.run(['su', '-c', 'cat /proc/net/if_inet6'], capture_output=True, text=True)
        Logger.info(f"DeadNet: get_ipv6_prefdata cmd result - {result}")
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                parts = line.strip().split()
                if parts[-1] == interface_name:
                    raw = parts[0]
                    preflen = int(parts[2], 16)
                    # Convert raw hex into proper IPv6 format
                    prefix = ":".join([raw[i:i + 4] for i in range(0, 16, 4)])
                    prefix = f"{prefix}::"
                    break
    except Exception as e:
        Logger.error(f"DeadNet: get_ipv6_prefdata error {e} - {traceback.format_exc()}")

    Logger.info(f"DeadNet: get_ipv6_prefdata success - {prefix} {preflen}")
    return prefix, preflen


def generate_random_mac() -> str:
    mac = [0x00, 0x16, 0x3e,  # locally administered MAC address range
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

