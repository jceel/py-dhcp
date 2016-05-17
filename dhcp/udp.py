#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import ipaddress
import enum
import struct


ETHERNET_HEADER_FMT = '!6s6sH'
IPV4_HEADER_FMT = '!BBHHHBBH4s4s'
UDP_HEADER_FMT = '!HHHH'


class EtherType(enum.IntEnum):
    IPv4 = 0x0800
    ARP = 0x0806


class UDPPacket(object):
    def __init__(self, **kwargs):
        # Ethernet header
        self.src_mac = None
        self.dst_mac = None
        self.ethertype = None
        # IP header
        self.version = None
        self.header_length = None
        self.tos = None
        self.length = None
        self.identification = None
        self.flags = None
        self.ttl = None
        self.protocol = None
        self.header_checksum = None
        self.src_address = None
        self.dst_address = None
        # UDP header
        self.src_port = None
        self.dst_port = None
        self.udp_length = None
        self.udp_checksum = None
        # Payload
        self.payload = None

        for k, v in kwargs.items():
            setattr(self, k, v)

    def unpack(self, data):
        self.dst_mac, self.src_mac, self.ethertype = \
            struct.unpack_from(ETHERNET_HEADER_FMT, data, 0)

        ihl, self.tos, self.length, self.identification, \
            self.flags, self.ttl, self.protocol, self.header_checksum, \
            self.src_address, self.dst_address = struct.unpack_from(IPV4_HEADER_FMT, data, 14)

        self.src_port, self.dst_port, self.udp_length, self.udp_checksum = \
            struct.unpack_from(UDP_HEADER_FMT, data, 34)

        self.version = ihl >> 4 & 0xf
        self.header_length = ihl & 0xf
        self.src_address = ipaddress.ip_address(self.src_address)
        self.dst_address = ipaddress.ip_address(self.dst_address)

    def pack(self):
        buffer = bytearray(
            struct.calcsize(ETHERNET_HEADER_FMT) +
            struct.calcsize(IPV4_HEADER_FMT) +
            struct.calcsize(UDP_HEADER_FMT) +
            len(self.payload)
        )

        ihl = self.header_length & (self.version << 4)

        struct.pack_into(
            ETHERNET_HEADER_FMT, buffer, 0,
            self.dst_mac, self.src_mac, self.ethertype
        )

        struct.pack_into(
            IPV4_HEADER_FMT, buffer, 14, ihl,
            self.tos, self.length, self.identification, self.flags, self.ttl,
            self.protocol, self.header_checksum, self.src_address, self.dst_address
        )

        struct.pack_into(
            UDP_HEADER_FMT, buffer, 34,
            self.src_port, self.dst_port, self.udp_length, self.udp_checksum
        )

    def dump(self, f):
        print(self.__dict__, file=f)
