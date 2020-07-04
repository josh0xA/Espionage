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

from core.config import *
from core.packet import Packet

'''
class FrameElements:
    # MAC Addresses for the destination and source
    # of the ethernet frame
    destination = _destination
    source = _source
    # Protocol Used (HTTP, UDP/TCP, etc..)
    protocol = _protocol
'''

class NetworkFrame(object):

    def retrieve_mac_address(self, bytes_address):
        '''
        Transforms raw socket address in bytes, to a readable mac address
        @param (bytes_address) - The data to be transformed
        @return string
        '''
        bytes_mapper = map('{:02x}'.format, bytes_address)
        mac_address = ':'.join(bytes_mapper).upper()

        return mac_address

    def unpack_ether_frame(self, frame_data):
        '''

        @param (frame_data) - Contents of the ethernet frame
        @return None
        '''
        cfg = Config()
        pk = Packet()
        nf = NetworkFrame()

        destination, source, protocol = pk.unpack_packet(cfg.ESPI_ETHERNET_FRAME_STR, frame_data, 14)

        return nf.retrieve_mac_address(destination), nf.retrieve_mac_address(source), socket.htons(protocol), frame_data[14:]
