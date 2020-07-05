#!/usr/bin/python3
'''
Copyright (C) 2020 Josh Schiavone - All Rights Reserved
You may use, distribute and modify this code under the
terms of the MIT license, which unfortunately won't be
written for another century.

You should have received a copy of the MIT license with
this file. If not, visit : https://opensource.org/licenses/MIT
'''

from scapy.all import srp, send, Ether, ARP
import os, sys, time

from core.config import *

class Route(object):
    def __init__(self, forward_path):
        '''
        Auto constructor
        @param (forward_path, type=string) - GNU/Linux IP routing path
        @return None
        '''
        self.forward_path = forward_path

    def ip_route_switch_on(self):
        '''
        Enables IP routing on host machine
        @param (self) - self
        @return None
        '''
        cfg = Config()
        with open(self.forward_path) as route_path:
            if route_path.read() == 1:
                cfg.ESPI_UNIX_LINUX_ROUTING_ON = True
                return
        with open(self.forward_path, "w") as route_path:
            print(1, file=route_path)

    def get_default_gateway(self):
        '''
        Returns the default gateway on the host machine
        @param (self) - self
        @return array[element] : element -> string
        '''
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][0]

class Address(object):
    def __init__(self, ip_address):
        '''
        Auto constructor
        @param (ip_address, type=string) - Target IP address
        @return None
        '''
        self.ip_address = ip_address

    def retrieve_arp_mac(self):
        '''
        Auto constructor
        @param (ip_address, type=string) - Target IP address
        @return bytarray/string
        '''
        cfg = Config()
        mac_address, ax = srp(Ether(dst=cfg.ESPI_MAC_ADDRESS_FORMAT) / ARP(pdst=self.ip_address), timeout=3, verbose=0)
        if mac_address:
            return mac_address[0][1].src
