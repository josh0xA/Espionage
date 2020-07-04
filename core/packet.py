'''
Copyright (C) 2020 Josh Schiavone - All Rights Reserved
You may use, distribute and modify this code under the
terms of the MIT license, which unfortunately won't be
written for another century.

You should have received a copy of the MIT license with
this file. If not, visit : https://opensource.org/licenses/MIT
'''

import struct
import socket
import textwrap

import httpcap
from scapy.all import *

from scapy.layers.http import HTTPRequest
from core.config import *

from urllib.parse import unquote

class HTTP(object):
    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data

class Packet(object):

    def transform_ip_4_address(self, dest_src_address):
        return '.'.join(map(str, dest_src_address))

    def unpack_packet(self, bytes_string, packet_data, array_value):
        cfg = Config()
        return struct.unpack(
            str(bytes_string), packet_data[:int(array_value)]
        )

    def handle_ipv4_packet(self, packet_data):
        pk = Packet()
        cfg = Config()

        __v_header_length__ = packet_data[0]
        __v_version__ = __v_header_length__ >> cfg.__version_header_shifter_length__
        __header_len__ = (__v_header_length__ & 15) * cfg.__version_header_shifter_length__

        ttl, proto, src, target = pk.unpack_packet(cfg.ESPI_IPV4_BYTES_STR, packet_data, 20)

        return __v_version__, __header_len__, ttl, proto, pk.transform_ip_4_address(src), pk.transform_ip_4_address(target), packet_data[__header_len__:]

    def handle_icmp_packet(self, packet_data):
        cfg = Config()
        pk = Packet()

        icmp_checksum, icmp_type, icmp_code = pk.unpack_packet(cfg.ESPI_ICMP_BYTES_STR, packet_data, 4)
        return icmp_checksum, icmp_type, icmp_code, packet_data[4:]

    def handle_raw_http_packet(self, packet_data):
        cfg = Config()
        pk = Packet()

        esp = Espionage()
        esp.print_espionage_noprefix("\t\tRaw HTTP Packet: ")
        try:
            raw_http_byteorder = HTTP(packet_data)
            byteorder_information = str(raw_http_byteorder.data).split('\n')
            for order in byteorder_information:
                esp.print_espionage_noprefix('\t\t\t' + str(order))
        except:
            print(espionage_textwrapper('\t\t\t', packet_data))

def sniff_url_from_http_packet(interface):
    if Interface(interface).is_interface_up():
        sniff(filter="port 80", prn=process_http_packet, iface=interface, store=False)
    else: sniff(filter="port 80", prn=process_http_packet, store=False)

def process_http_packet(httppacket):
    esp = Espionage()
    cfg = Config()
    keywords = ['pass', 'password', 'usr', 'username', 'user', 'pwd']
    try:
        if httppacket.haslayer(HTTPRequest):
            url = httppacket[HTTPRequest].Host.decode()
            url_sub_dir = httppacket[HTTPRequest].Path.decode()

            packet_url = url + url_sub_dir

            packet_ip_address = httppacket[IP].src
            # Fetch the HTTP request method (GET or POST)
            http_method = httppacket[HTTPRequest].Method.decode()
            esp.print_espionage_noprefix(f"[+] {packet_ip_address} <requested> {packet_url} with {http_method}", color=True)
            if httppacket.haslayer(Raw) and http_method == "POST":
                pretty_raw_data = str(httppacket[Raw]).strip("{}b")
                esp.print_espionage_notab(f"{cfg.ESPI_ASCII_DOWN_ARROW} > Raw Data (possible credentials): " + pretty_raw_data.replace('&', ' | '))
    except IndexError:
        pass
