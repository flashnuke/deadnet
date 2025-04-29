import re
import random
import ipaddress
import traceback
import subprocess

from typing import Tuple
from jnius import autoclass
from kivy.logger import Logger
from functools import lru_cache

from .output_utils import DEADNET_PREF

NET_UNDEFINED = "null"
IFACE_DEFAULT_NAME = "wlan0"


def is_unknown_ssid(ssid: str) -> bool:
    if not ssid:
        return True
    ssid_clean = ssid.strip().lower().replace('"', '')
    return ssid_clean == '<unknown ssid>'


@lru_cache(maxsize=10)
def get_device_mac_address_su(iface: str) -> str:
    try:
        result = subprocess.run(['su', '-c', f'cat /sys/class/net/{iface}/address'], capture_output=True, text=True)
        Logger.info(f"{DEADNET_PREF}: get_device_mac_address_su cmd result - {result}")
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: get_device_mac_address_su error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


@lru_cache(maxsize=10)
def get_if_addr(iface: str) -> str:
    result = subprocess.run(['su', '-c', f'ip -4 addr show dev {iface}'], capture_output=True, text=True)
    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
    if match:
        return match.group(1)
    else:
        Logger.error(f"{DEADNET_PREF}: get_if_addr cmd missing match, result - {result}")
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
        Logger.error(f"{DEADNET_PREF}: get_ssid_name error {e} - {traceback.format_exc()}")
    return ssid_name


def get_net_iface_name() -> str:
    try:
        result = subprocess.run(['su', '-c', 'getprop wifi.interface'], capture_output=True, text=True)
        Logger.info(f"{DEADNET_PREF}: get_net_iface_name cmd getprop result - {result}")
        iface_name = result.stdout.strip()
        if False: #iface_name:
            return iface_name
        else:  # fallback: parse /proc/net/wireless
            Logger.error(f"{DEADNET_PREF}: getprop cmd failed, trying fallback...")
            try:
                fallback_result = subprocess.run(['su', '-c', 'cat /proc/net/wireless'], capture_output=True, text=True)
                Logger.info(f"{DEADNET_PREF}: get_net_iface_name cmd 'cat /proc/net/wireless' result - {fallback_result}")
                lines = fallback_result.stdout.splitlines()
                for line in lines[2:]: # skip headers (first 2 lines)
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            iface = parts[0].strip(':').strip()
                            status = parts[2]
                            try:
                                status_val = float(status)
                                if status_val > 0:  # has some link quality (traffic)
                                    Logger.info(f"{DEADNET_PREF}: fallback iface detected - {iface}")
                                    return iface
                            except ValueError:
                                continue

            except Exception as fallback_err:
                Logger.error(f"{DEADNET_PREF}: error during fallback parsing /proc/net/wireless {fallback_err}")

    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: get_net_iface_name error {e} - {traceback.format_exc()}")
    Logger.info(f"{DEADNET_PREF}: get_net_iface_name failed, returning default {IFACE_DEFAULT_NAME}")
    return IFACE_DEFAULT_NAME


@lru_cache(maxsize=10)
def get_ipv6_with_su(iface: str) -> str:
    try:
        su_cmd = f"cat /proc/net/if_inet6"
        result = subprocess.run(['su', '-c', su_cmd], capture_output=True, text=True)
        Logger.info(f"{DEADNET_PREF}: get_ipv6_with_su cmd result - {result}")
        for line in result.stdout.strip().splitlines():
            parts = line.strip().split()
            if parts[-1] == iface:
                raw = parts[0]
                ipv6 = ':'.join([raw[i:i + 4] for i in range(0, len(raw), 4)])
                return ipv6
    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: get_ipv6_with_su error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


@lru_cache(maxsize=10)
def mac_to_ipv6_ll(mac: str) -> str:
    try:
        parts = mac.split(':')
        if len(parts) != 6:
            raise ValueError(f"Invalid MAC: {mac}")
        b = [int(p, 16) for p in parts]
        b[0] ^= 0x02
        eui64 = bytes(b[:3] + [0xFF, 0xFE] + b[3:])
        ipv6_int = int.from_bytes(eui64, 'big') | (0xFE80000000000000 << 64)
        return str(ipaddress.IPv6Address(ipv6_int))
    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: mac_to_ipv6_ll error {e} - {traceback.format_exc()}")
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
        Logger.error(f"{DEADNET_PREF}: get_gateway_ipv4 error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


@lru_cache(maxsize=10)
def get_gateway_mac(iface: str) -> str:
    try:
        cmd = 'ip neighbor show default'
        result = subprocess.run(['su', '-c', cmd], capture_output=True, text=True, check=True)
        Logger.info(f"{DEADNET_PREF}: get_gateway_mac cmd result - {result}")
        output = result.stdout.strip()
        # parse each line for "lladdr" on our interface
        for line in output.splitlines():
            cols = line.split()
            # example cols: ['192.168.1.1', 'dev', 'wlan0', 'lladdr', 'aa:bb:cc:dd:ee:ff', 'REACHABLE']
            if len(cols) >= 5 and cols[3] == 'lladdr' and cols[4] != '<incomplete>':
                if cols[2] == iface:
                    return cols[4]
    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: get_gateway_mac error {e} - {traceback.format_exc()}")
    return NET_UNDEFINED


def init_gateway() -> Tuple[str, str, str, str]:
    gateway_ipv4 = gateway_ipv6 = iface = gateway_hwaddr = NET_UNDEFINED

    try:
        iface = get_net_iface_name()
        if is_unknown_ssid(iface):
            raise Exception("unable to get iface_name")
        gateway_ipv4 = get_gateway_ipv4()
        gateway_hwaddr = get_gateway_mac(iface)
        gateway_ipv6 = mac_to_ipv6_ll(gateway_hwaddr)
    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: init_gateway error {e} - {traceback.format_exc()}")

    Logger.info(f"{DEADNET_PREF}: init_gateway success - {gateway_ipv4} {gateway_ipv6} {gateway_hwaddr} {iface}")
    return gateway_ipv4, gateway_ipv6, gateway_hwaddr, iface


@lru_cache(maxsize=10)
def get_ipv6_prefdata(interface_name: str) -> Tuple[str, int]:
    prefix = ""
    preflen = 0
    try:
        result = subprocess.run(['su', '-c', 'cat /proc/net/if_inet6'], capture_output=True, text=True)
        Logger.info(f"{DEADNET_PREF}: get_ipv6_prefdata cmd result - {result}")
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
        Logger.error(f"{DEADNET_PREF}: get_ipv6_prefdata error {e} - {traceback.format_exc()}")

    Logger.info(f"{DEADNET_PREF}: get_ipv6_prefdata success - {prefix} {preflen}")
    return prefix, preflen


def generate_random_mac() -> str:
    mac = [0x00, 0x16, 0x3e,  # locally administered MAC address range
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

