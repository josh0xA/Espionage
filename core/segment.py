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

class Segment(object):

    def load_tcp_segment(self, segment_data):
        cfg = Config()
        pk = Packet()

        (reserved_byte_offset, source_port_value, destination_port_value, ack, seq) = pk.unpack_packet(cfg.ESPI_TCP_SEGMENT_FORMAT, segment_data,
        8)

        __offset__ = (reserved_byte_offset >> 12) * cfg.__version_header_shifter_length__
        __urg_flag__ = (reserved_byte_offset & 32) >> cfg.__flag_urg_shift_value__
        __ack_flag__ = (reserved_byte_offset & 32) >> cfg.__flag_ack_shift_value__
        __psh_flag__ = (reserved_byte_offset & 32) >> cfg.__flag_psh_shift_value__
        __rst_flag__ = (reserved_byte_offset & 32) >> cfg.__flag_rst_shift_value__
        __syn_flag__ = (reserved_byte_offset & 32) >> cfg.__flag_syn_fin_shift_value__
        __fin_flag__ = (reserved_byte_offset & 32) >> cfg.__flag_syn_fin_shift_value__

        return source_port_value, destination_port_value, seq, ack, __urg_flag__,
        __ack_flag__, __psh_flag__, __rst_flag__, __syn_flag__, __fin_flag__, segment_data[__offset__:]

    def load_udp_segment(self, segment_data):
        cfg = Config()
        pk = Packet()

        udp_port_source, udp_port_destination, udp_size = pk.unpack_packet(cfg.ESPI_UDP_SEGMENT_FORMAT, segment_data, 8)
        return udp_port_source, udp_port_destination, udp_size, segment_data[8:]
