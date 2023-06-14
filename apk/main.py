import re
import os
import sys
import threading
import netifaces

from subprocess import call
from utils import *
from deadnet import DeadNet
from scapy.all import *

from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.image import Image
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.gridlayout import GridLayout
from kivy.graphics import Color, Rectangle


class MainApp(App):
    _WIDGET_PROPERTIES = {
        "settings_bg_color": [1, 1, 1, 0.15],
        "settings_fg_color": [1, 1, 1, 1],
        "settings_text_size": 40,
        "button_text_size": 65,
        "button_sz_hint": (0.25, None),
        "button_pos_hint": {'center_x': .5, 'center_y': .5}
    }

    def __init__(self, *args, **kwargs):
        self._GATEWAY_IPV4, self._GATEWAY_HWDDR, self._IFACE = self.init_gateway()
        self._abort_lck = threading.RLock()
        self._deadnet_ins = None
        self.main_layout = None
        self.settings_layout = None
        self.output_label = None
        self.buttons_layout = None
        self.button_start, self.button_stop = None, None
        self.credit_label = None
        self.img = None

        super().__init__(*args, **kwargs)

    def build(self):
        self.main_layout = BoxLayout(orientation="vertical")
        self.img = Image(source='assets/banner.png')
        self.main_layout.add_widget(self.img)

        self.settings_layout = GridLayout(cols=2,
                                          padding=33,
                                          size_hint_y=0.85)
        iface_label = Label(text='- Network interface',
                            halign="left",
                            valign="middle",
                            font_size=self._WIDGET_PROPERTIES["settings_text_size"])
        iface_label.bind(size=iface_label.setter('text_size'))
        self.settings_layout.add_widget(iface_label)
        self.settings_layout.add_widget(
            TextInput(text=self._IFACE,
                      size_hint=(0.5, None),
                      height=90,
                      background_color=self._WIDGET_PROPERTIES["settings_bg_color"],
                      foreground_color=self._WIDGET_PROPERTIES["settings_fg_color"],
                      font_size=self._WIDGET_PROPERTIES["settings_text_size"],
                      multiline=False,
                      on_text=lambda instance, value: setattr(self, "_IFACE", value)))

        gateway_label = Label(text='- IPv4 gateway',
                              halign="left",
                              valign="middle",
                              font_size=self._WIDGET_PROPERTIES["settings_text_size"])
        gateway_label.bind(size=gateway_label.setter('text_size'))
        self.settings_layout.add_widget(gateway_label)
        self.settings_layout.add_widget(
            TextInput(text=self._GATEWAY_IPV4,
                      size_hint=(0.5, None),
                      height=90,
                      background_color=self._WIDGET_PROPERTIES["settings_bg_color"],
                      foreground_color=self._WIDGET_PROPERTIES["settings_fg_color"],
                      font_size=self._WIDGET_PROPERTIES["settings_text_size"],
                      multiline=False,
                      on_text=lambda instance, value: setattr(self, "_GATEWAY_IPV4", value)))

        self.main_layout.add_widget(self.settings_layout)

        self.output_label = Label(text='ready...',
                                  bold=True,
                                  markup=True,
                                  pos_hint={'center_x': .5, 'center_y': 1})
        self.main_layout.add_widget(self.output_label)

        self.buttons_layout = GridLayout(cols=2,
                                         padding=33,
                                         size_hint_y=0.85)
        self.button_start = Button(text=f'{GREEN}{BOLD}Start{COLOR_RESET}{BOLD_RESET}',
                                   font_size=self._WIDGET_PROPERTIES["button_text_size"],
                                   markup=True,
                                   size_hint=self._WIDGET_PROPERTIES["button_sz_hint"],
                                   height=220,
                                   pos_hint=self._WIDGET_PROPERTIES["button_pos_hint"],
                                   background_color=self._WIDGET_PROPERTIES["settings_bg_color"])
        self.button_start.bind(on_press=self.on_start_press)
        self.buttons_layout.add_widget(self.button_start)

        self.button_stop = Button(text=f'{RED}{BOLD}Stop{COLOR_RESET}{BOLD_RESET}',
                                  font_size=self._WIDGET_PROPERTIES["button_text_size"],
                                  markup=True,
                                  size_hint=self._WIDGET_PROPERTIES["button_sz_hint"],
                                  height=220,
                                  pos_hint=self._WIDGET_PROPERTIES["button_pos_hint"],
                                  background_color=self._WIDGET_PROPERTIES["settings_bg_color"])
        self.button_stop.bind(on_press=self.on_stop_press)
        self.buttons_layout.add_widget(self.button_stop)
        self.main_layout.add_widget(self.buttons_layout)

        self.credit_label = Label(text=f'written by {BLUE}[u][ref=https://github.com/flashnuke]@flashnuke[/ref]{COLOR_RESET}[/u]',
                                  bold=True,
                                  markup=True,
                                  pos_hint={'center_x': .5, 'center_y': 1},
                                  on_ref_press=self.on_ref_credit_press)
        self.main_layout.add_widget(self.credit_label)

        return self.main_layout

    def on_ref_credit_press(self, *args, **kwargs):
        import webbrowser
        webbrowser.open("https://github.com/flashnuke")

    def on_start_press(self, instance):
        threading.Thread(target=self.do_attack, args=tuple()).start()  # should be a separate thread

    def do_attack(self):
        with self._abort_lck:
            if self._deadnet_ins:
                return
            try:
                self._deadnet_ins = DeadNet(self._IFACE, self._GATEWAY_IPV4, self._GATEWAY_HWDDR, self.printf)
            except Exception as exc:
                self.printf(f"error during setup -> {exc}")
                return
        self._deadnet_ins.start_attack()

    def on_stop_press(self, instance):
        with self._abort_lck:
            if self._deadnet_ins:
                self._deadnet_ins.user_abort()
            self._deadnet_ins = None

    def printf(self, text, fit_size=False):
        # use only inside Deadnet to maintain format
        self.output_label.text = text
        if fit_size:  # needed for big msgs such as exceptions
            self.output_label.text_size = self.output_label.size

    @staticmethod
    def init_gateway():
        gateway_ipv4, iface, gateway_hwaddr = "undefined", "undefined", "undefined"
        gateways = netifaces.gateways()
        for k, v in gateways.items():
            if len(v) == 0:
                continue
            elif k == 2:
                d = v[0]
                gateway_ipv4 = d[0]
                iface = d[1]
                addresses = [item['addr'] for sublist in netifaces.ifaddresses(iface).values() for item in sublist if re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", item['addr'])]
                gateway_hwaddr = addresses[0]
                if not gateway_hwaddr:
                    pass

        return gateway_ipv4, gateway_hwaddr, iface


if __name__ == "__main__":
    call(["su"])  # for root
    app = MainApp()
    app.run()
