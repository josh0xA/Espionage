'''
Copyright (C) 2020 Josh Schiavone - All Rights Reserved
You may use, distribute and modify this code under the
terms of the MIT license, which unfortunately won't be
written for another century.
You should have received a copy of the MIT license with
this file. If not, visit : https://opensource.org/licenses/MIT
'''

'''
Espionage - The Packet Intercepting Tool For Linux
        Developed By: Josh Schiavone
             josh@profify.ca
'''

'''
                                 NOTICE
The developer of this program, Josh Schiavone, written the following code
for educational and ethical purposes only. The data sniffed/intercepted is
not to be used for malicous intent. Josh Schiavone is not responsible or liable
for misuse of this penetration testing tool. May God bless you all.
'''

import os, sys
import time
import socket

import struct
import textwrap

import requests
import argparse
import subprocess

from termcolor import cprint, colored

from ext.banner import *
from core.espionage_http.esphttpsniff import *

from core.config import *
from core.packet import Packet
from core.frame import NetworkFrame
from core.optformat import *

from arp.cachepoison import *
from arp.iproute import *

global pcap_file_name # "Global variables are bad!" - NSA's programming tips

__version__ = '1.2'
__author__ = 'Josh Schiavone'
__license__ = 'MIT'

def espionage_main():
    esp = Espionage()
    p = Platform()
    cfg = Config()
    nf = NetworkFrame()
    opt = ProtoOutput()
    pk = Packet()
    seg = Segment()
    so = SegmentOutput()

    p.EspionageClear()
    p.GetOperatingSystemDescriptor()
    time.sleep(0.7)
    LoadEspionageBanner()
    time.sleep(0.7)

    parser = argparse.ArgumentParser()

    parser.add_argument("--version",
                        help="returns the packet sniffers version.",
                        action="store_true")

    parser.add_argument("-n",
                        "--normal",
                        help="executes a cleaner interception, less sophisticated.",
                        action="store_true")

    parser.add_argument("-v",
                        "--verbose",
                        help="(recommended) executes a more in-depth packet interception/sniff.",
                        action="store_true")

    parser.add_argument("-url",
                        "--urlonly",
                        help="only sniffs visited urls using http/https.",
                        action="store_true")

    parser.add_argument("-o",
                        "--onlyhttp",
                        help="sniffs only tcp/http data, returns urls visited.",
                        action="store_true")

    parser.add_argument("-ohs",
                        "--onlyhttpsecure",
                        help="sniffs only https data, (port 443).",
                        action="store_true")

    parser.add_argument("-hr",
                        "--httpraw",
                        help="displays raw packet data (byte order) recieved or sent on port 80.",
                        action="store_true")


    file_arg_section = parser.add_argument_group('(Recommended) arguments for data output (.pcap)')
    file_arg_section.add_argument("-f",
                        "--filename",
                        help="name of file to store the output (make extension '.pcap').",
                        type=str)

    required_arg_section = parser.add_argument_group('(Required) arguments required for execution')
    required_arg_section.add_argument("-i",
                              "--iface",
                               help="specify network interface (ie. wlan0, eth0, wlan1, etc.)",
                               type=str,
                               required=True)

    spoofer_section = parser.add_argument_group('(ARP Spoofing) required arguments in-order to use the ARP Spoofing utility')
    spoofer_section.add_argument("-t",
                                "--target",
                                required=False)

    args = parser.parse_args()

    pcap_file_name = str(args.filename)

    try:
        __socket__ = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if Interface(args.iface).is_interface_up():
            __socket__.setsockopt(socket.SOL_SOCKET, 25, bytearray(str.encode(args.iface)))
        else: pass
        cfg.ESPIONAGE_PROCESS_ACTIVE = True

    except PermissionError as pe:
        cprint("Must be ran as root.", 'red', attrs=['bold'])
        sys.exit(cfg.ESPI_ERROR_CODE_STANDARD)

    if args.version:
        cprint("\t  Version: {}\n".format(__version__), 'cyan', attrs=['bold'])

    elif args.normal:
        try:
            while cfg.ESPIONAGE_PROCESS_ACTIVE:
                raw_data, addr = __socket__.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = nf.unpack_ether_frame(raw_data)

                print(BOLD + G + "[espionage]>" + W + BOLD + 'Ethernet Frame: ')
                esp.print_espionage_notab('Destination: {}, Source: {}, Protocol: {}\n'.format(dest_mac, src_mac, eth_proto))

                (packet_version, packet_header_length, packet_ttl, packet_protocol, packet_source, packet_destination, pkdata) = pk.handle_ipv4_packet(data)
                print(pkdata)

                if eth_proto == 8:
                    opt.__write_ipv4_normal_output__(data)

                    if args.filename:
                        PCAP(pcap_file_name).write_to_pcap_file("\nIPv4 Packet Contents {}".format(cfg.ESPI_ASCII_DOWN_ARROW))
                        PCAP(pcap_file_name).write_to_pcap_file("\t <-- Protocol: {}, Source: {}, Destination: {}".format(packet_protocol, packet_source, packet_destination))
                    else: pass

                    if packet_protocol == 1:
                        (icmp_packet_type, icmp_packet_code, icmp_check_summation, icmp_packet_data) = pk.handle_icmp_packet(data)
                        opt.__write_icmp_normal_output__(data)
                        if args.filename:
                            PCAP(pcap_file_name).write_to_pcap_file("ICMP Contents {}".format(cfg.ESPI_ASCII_DOWN_ARROW))
                            PCAP(pcap_file_name).write_to_pcap_file("ICMP Checksum: {}, ICMP Type: {}, ICMP Code: {}".format(icmp_check_summation, icmp_packet_type,icmp_packet_code))
                        else: pass

                    elif packet_protocol == 6:
                        (segment_source_port, segment_destination_port, segment_sequence, segment_acknowledgment, __urg_flag__, __ack_flag__,
                        __psh_flag__, __rst_flag__, __syn_flag__, __fin_flag__) = pk.unpack_packet(cfg.ESPI_TCP_STRUCT_SEGMENT_FORMAT, data, 24)

                        so.__write_tcp_segment_normal_output__(raw_data)

                        if len(data) > cfg.ESPI_SUCCESS_CODE_STANDARD and args.httpraw:
                            if segment_source_port == cfg.ESPI_HTTP_DEFAULT_PORT or segment_destination_port == cfg.ESPI_HTTP_DEFAULT_PORT:
                                pk.handle_raw_http_packet(data)
                            else:
                                esp.print_espionage_noprefix('\t\t' + "Raw TCP/Raw-no-http Packet Bytes: ")
                                print(espionage_textwrapper('\t\t\t', data))
                        else: pass
                        if args.filename:
                            PCAP(pcap_file_name).write_to_pcap_file("\n\tTCP Segment {}".format(cfg.ESPI_ASCII_DOWN_ARROW))
                            PCAP(pcap_file_name).write_to_pcap_file("\n\t\tSource Port # {}, Destination Port # {}, [Sequence] {}".format(segment_source_port,
                            segment_destination_port, segment_sequence))
                        else: pass
                    elif packet_protocol == 17:
                        (segment_source_port, segment_destination_port, segment_length, segdata) = seg.load_udp_segment(data)
                        so.__write_udp_segment_normal_verbose_output__(segdata)
                        if args.filename:
                            PCAP(pcap_file_name).write_to_pcap_file("\n\tUDP Segment (len={}) {}".format(segment_length, cfg.ESPI_ASCII_DOWN_ARROW))
                            PCAP(pcap_file_name).write_to_pcap_file("\n\t\tSource Port: {}, Target Port: {}".format(segment_source_port, segment_destination_port))
                        else: pass

        except KeyboardInterrupt:
            if args.filename:
                print(BOLD + R + "\nExiting Espionage Interception.\n" + BOLD + G + "Packet capture saved to: {}".format(os.path.realpath(pcap_file_name)) + END)
            else: print(BOLD + R + "\nExiting Espionage Interception.\n" + BOLD + C + "Packet capture not written to file.\n" + END)


    elif args.verbose:
        try:
            while True:
                raw_data, addr = __socket__.recvfrom(65536)
                dest_mac, src_mac, eth_proto, data = nf.unpack_ether_frame(raw_data)

                print(BOLD + G + "[espionage]>" + W + BOLD + 'Ethernet Frame: ')
                esp.print_espionage_notab('Destination: {}, Source: {}, Protocol: {}\n'.format(dest_mac, src_mac, eth_proto))

                (packet_version, packet_header_length, packet_ttl, packet_protocol, packet_source, packet_destination, pkdata) = pk.handle_ipv4_packet(data)

                if eth_proto == 8:
                    opt.__write_ipv4_verbose_output__(data)
                    if args.filename:
                            PCAP(pcap_file_name).write_to_pcap_file("\nIPv4 Packet Contents {}".format(cfg.ESPI_ASCII_DOWN_ARROW))
                            PCAP(pcap_file_name).write_to_pcap_file("\t <-- Protocol: {}, Source: {}, Destination: {}".format(packet_protocol, packet_source, packet_destination))
                    else: pass

                    if packet_protocol == 1:
                        (icmp_packet_type, icmp_packet_code, icmp_check_summation, icmp_packet_data) = pk.handle_icmp_packet(data)
                        opt.__write_icmp_verbose_output__(data)
                        if args.filename:
                            PCAP(pcap_file_name).write_to_pcap_file("ICMP Contents {}".format(cfg.ESPI_ASCII_DOWN_ARROW))
                            PCAP(pcap_file_name).write_to_pcap_file("ICMP Checksum: {}, ICMP Type: {}, ICMP Code: {}".format(icmp_check_summation, icmp_packet_type,icmp_packet_code))
                            PCAP(pcap_file_name).write_to_pcap_file("\t\tICMP Data: {}".format(icmp_packet_data))
                        else: pass

                    elif packet_protocol == 6:
                        (segment_source_port, segment_destination_port, segment_sequence, segment_acknowledgment, __urg_flag__, __ack_flag__,
                        __psh_flag__, __rst_flag__, __syn_flag__, __fin_flag__) = pk.unpack_packet(cfg.ESPI_TCP_STRUCT_SEGMENT_FORMAT, data, 24)
                        so.__write_tcp_segment_verbose_output__(raw_data)

                        if len(data) > cfg.ESPI_SUCCESS_CODE_STANDARD and args.httpraw:
                            if segment_source_port == cfg.ESPI_HTTP_DEFAULT_PORT or segment_destination_port == cfg.ESPI_HTTP_DEFAULT_PORT:
                                pk.handle_raw_http_packet(data)
                            else:
                                esp.print_espionage_noprefix('\t\t' + "Raw TCP/Raw-no-http Packet Bytes: ")
                                print(espionage_textwrapper('\t\t\t', raw_data))
                        else: pass

                        if args.filename:
                            PCAP(pcap_file_name).write_to_pcap_file("\n\tTCP Segment {}".format(cfg.ESPI_ASCII_DOWN_ARROW))
                            PCAP(pcap_file_name).write_to_pcap_file("\n\t\tSource Port # {}, Destination Port # {}, [Sequence] {}".format(segment_source_port,
                            segment_destination_port, segment_sequence))
                            # Write TCP Segment flags to file
                            PCAP(pcap_file_name).write_to_pcap_file("\n\t\tTCP Segment Flags")
                            PCAP(pcap_file_name).write_to_pcap_file("\n\t\tFLAG_URG: {}, FLAG_ACK: {}, FLAG_PSH: {}, FLAG_RST: {}".format(__urg_flag__,
                            __ack_flag__, __psh_flag__, __rst_flag__))

                        else: pass

                    elif packet_protocol == 17:
                        (segment_source_port, segment_destination_port, segment_length, segdata) = seg.load_udp_segment(data)
                        so.__write_udp_segment_normal_verbose_output__(segdata)
                        if args.filename:
                            PCAP(pcap_file_name).write_to_pcap_file("\n\tUDP Segment (len={}) {}".format(segment_length, cfg.ESPI_ASCII_DOWN_ARROW))
                            PCAP(pcap_file_name).write_to_pcap_file("\n\t\tSource Port: {}, Target Port: {}".format(segment_source_port, segment_destination_port))
                        else: pass


        except KeyboardInterrupt:
            if args.filename:
                print(BOLD + R + "\nExiting Espionage Interception.\n" + BOLD + G + "Packet capture saved to: {}".format(os.path.realpath(pcap_file_name)) + END)
            else: print(BOLD + R + "\nExiting Espionage Interception.\n" + BOLD + C + "Packet capture not written to file.\n" + END)

    elif args.urlonly:
        cfg = Config()
        esp = Espionage()

        esp.print_espionage_message("Visited URLs will be displayed below.\n", True)
        sniff_url_from_http_packet(args.iface)

    elif args.onlyhttp:
        it = InterfaceHandle()
        cfg = Config()
        try:
            for sysiface in it.get_system_interfaces():
                if args.iface in sysiface:
                    if Interface(sysiface).is_interface_up():
                        pk = Packet()
                        cprint("Interface: {} is active.".format(args.iface), 'green', attrs=['bold'])
                        cfg.ESPI_NET_INTERFACE_ACTIVE = True
                        break

            if Interface(args.iface).is_interface_up() == False:
                cprint("Interface: {} is not-active.".format(args.iface), 'red', attrs=['bold'])
                cfg.ESPI_NET_INTERFACE_ACTIVE = False

            if cfg.ESPI_NET_INTERFACE_ACTIVE:
                ESPHTTPHandle(sysiface, cfg.ESPI_HTTP_DEFAULT_PORT).sniff_basic_http()
        except KeyboardInterrupt:
            print(BOLD + R + "\n[!] Exiting Espionage HTTPS Interception.\n" + END)

    elif args.onlyhttpsecure:
        it = InterfaceHandle()
        cfg = Config()
        try:
            for sysiface in it.get_system_interfaces():
                if args.iface in sysiface:
                    if Interface(sysiface).is_interface_up():
                        pk = Packet()
                        cprint("Interface: {} is active.".format(args.iface), 'green', attrs=['bold'])
                        cfg.ESPI_NET_INTERFACE_ACTIVE = True
                        break

            if Interface(args.iface).is_interface_up() == False:
                cprint("Interface: {} is not-active.".format(args.iface), 'red', attrs=['bold'])
                cfg.ESPI_NET_INTERFACE_ACTIVE = False

            if cfg.ESPI_NET_INTERFACE_ACTIVE:
                ESPHTTPSecureHandle(sysiface, cfg.ESPI_TCP_HTTPS_DEFAULT_PORT).sniff_basic_https()

        except KeyboardInterrupt:
            print(BOLD + R + "\n[!] Exiting Espionage HTTPS Interception.\n" + END)

    elif args.target:
        Route(cfg.ESPI_UNIX_LINUX_IP_ROUTE_PATH).ip_route_switch_on()
        default_gateway = Route(cfg.ESPI_UNIX_LINUX_IP_ROUTE_PATH).get_default_gateway()
        try:
            while True:
                ARPHandle(args.target, default_gateway).spoof_arp()
                ARPHandle(default_gateway, args.target).spoof_arp()
                time.sleep(1)
        except KeyboardInterrupt:
            print(BOLD + R + "\n[!] Quitting ARP Spoof. Restoring Network...\n" + END)
            ARPHandle(args.target, default_gateway).restore_network()
            ARPHandle(default_gateway, args.target).restore_network()

if __name__ == "__main__":
    espionage_main()
