from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.gridlayout import GridLayout
import time
from deadnet import DeadNet
#deadnet._PRINT_LOGO = False
import jnius
from jnius import autoclass
#import subprocess
#import os
# os.system('python ../deadnet.py')
from kivy.uix.boxlayout import BoxLayout
from scapy.all import *
import subprocess
import netifaces
import threading
# stdout_manager = select.poll()
class MainApp(App):
    _GATEWAY = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
    def build(self):
        self._GATEWAY = "127.0.0.1"
        self.main_layout = BoxLayout(orientation="vertical")

        self.symbol_label = Label(text='DeadNet',
                                  bold=True,
                                  # size_hint=(.5, .5),
                                  # font_size=100,
                                  pos_hint={'center_x': .5, 'center_y': 1})
        self.main_layout.add_widget(self.symbol_label)  # add price label
        self.button_test = Button(text='Start',
                                     size_hint=(None, None),
                                     pos_hint={'center_x': .5, 'center_y': .5})
        self.button_test.bind(on_press=self.on_start_press)
        self.main_layout.add_widget(self.button_test)
        self.gateway = None

        # textinput = TextInput(text=self._GATEWAY, multiline=False,
        #                       foreground_color=[1, 1, 0, 1],
        #                       background_color=[0, 0, 0.15, 0.15],
        #                       pos_hint={'center_x': .5, 'center_y': .5},
        #                       size_hint=(None, None))
        # textinput.bind(text=self.on_text)
        # self.main_layout.add_widget(textinput)


        return self.main_layout
    ##,
                           #   background_color=[0, 0, 0, 0]
    #
    def on_text(self, instance, value):
        self.gateway=value
        print(f'gateway -> { self.gateway}')


    def on_start_press(self, instance):
        print(netifaces.interfaces())
        gateways = netifaces.gateways()
        print(gateways)
        print("test")
        xxx = str()
        gateway = str()
        iface = str()
        gateway_hw = str()
   
        from subprocess import call
        call(["su"])
        for k, v in gateways.items():
            if len(v) == 0:
                continue
            elif k == 2:
                print("boba")
                print(k)
                print(v)
                xxx = v[0]
                gateway = xxx[0]
                iface = xxx[1]
                print(gateway)
                print(iface)
                gateway_hw = netifaces.ifaddresses(iface).get(17)[0].get('addr')
        
        print("im here boi")
        DeadNet(iface ,24, 5, gateway,
                       False, 64, gateway_hw).start_attack()


        # return
    def on_enter(self, instance, value=None):
        print('User pressed enter in', instance)
        print("-> " + self.gateway)



if __name__ == "__main__":
    app = MainApp()
    app.run()


