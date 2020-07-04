'''
Copyright (C) 2020 Josh Schiavone - All Rights Reserved
You may use, distribute and modify this code under the
terms of the MIT license, which unfortunately won't be
written for another century.

You should have received a copy of the MIT license with
this file. If not, visit : https://opensource.org/licenses/MIT
'''

import os, sys, time

from core.config import *
from core.packet import *
from core.frame import NetworkFrame
from core.optformat import *

from scapy.all import *
from scapy.layers.http import HTTPRequest

from core.espionage_http.esphttpsniffopt import *

class ESPHTTPHandle(object):
    def __init__(self, interface, portnumber):
        self.interface = interface
        self.portnumber = portnumber

    def sniff_basic_http(self):
        core.config.http_pckts = []
        for packet in sniff(filter="tcp port 80", iface=self.interface, prn=process_http_packet, store=True):
            core.config.http_pckts.append(packet)

class ESPHTTPSecureHandle(object):
    def __init__(self, interface, portnumber):
        self.interface = interface
        self.portnumber = portnumber

    def sniff_basic_https(self):
        core.config.http_pckts = []
        for packet in sniff(filter="port 443", iface=self.interface, prn=process_http_packet, store=True):
            core.config.http_pckts.append(packet)
