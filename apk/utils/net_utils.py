import subprocess

from jnius import autoclass


def get_ipv6_with_su(iface):
    try:
        su_cmd = f"cat /proc/net/if_inet6"
        result = subprocess.run(['su', '-c', su_cmd], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"@@@@@ su command failed: {result.stderr.strip()}")
            return "undefined" # todo undefined?

        for line in result.stdout.strip().splitlines():
            parts = line.strip().split()
            if parts[-1] == iface:
                raw = parts[0]
                ipv6 = ':'.join([raw[i:i + 4] for i in range(0, len(raw), 4)])
                return ipv6
    except Exception as e:
        print(f"@@@@@ Exception in get_ipv6_with_su: {e}")
    return "undefined" # todo undefined?


def get_gateway_ipv4():
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
