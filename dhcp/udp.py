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
import random
import socket
from .utils import format_mac, pack_mac


ETHERNET_HEADER_FMT = '!6s6sH'
ETHERNET_HEADER_LENGTH = 14
IPV4_HEADER_FMT = '!BBHHHBBH4s4s'
IPV4_HEADER_LENGTH = 20
UDP_HEADER_FMT = '!HHHH'
UDP_HEADER_LENGTH = 8


def checksum(data):
    """ Compute the Internet Checksum of the supplied data.  The
    checksum is initialized to zero.  Place the return value in
    the checksum field of a packet.  When the packet is received,
    check the checksum by passing in the packet.  If the result is
    zero, then the checksum has not detected an error.
    """

    sum = 0
    # make 16 bit words out of every two adjacent 8 bit words in the packet
    # and add them up
    for i in range(0, len(data), 2):
        if i + 1 >= len(data):
            sum += data[i] & 0xFF
        else:
            w = ((data[i] << 8) & 0xFF00) + (data[i + 1] & 0xFF)
            sum += w

    # take only 16 bits out of the 32 bit sum and add up the carries
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    # one's complement the result
    sum = ~sum
    return sum & 0xFFFF


class EtherType(enum.IntEnum):
    IPv4 = 0x0800
    ARP = 0x0806


class UDPPacket(object):
    def __init__(self, **kwargs):
        # Ethernet header
        self.src_mac = None
        self.dst_mac = None
        self.ethertype = EtherType.IPv4

        # IP header
        self.version = 4
        self.header_length = 5
        self.tos = 0
        self.length = None
        self.identification = random.randint(0, 2**16 - 1)
        self.flags = 0
        self.ttl = 20
        self.protocol = socket.IPPROTO_UDP
        self.header_checksum = 0
        self.src_address = None
        self.dst_address = None

        # UDP header
        self.src_port = None
        self.dst_port = None
        self.udp_length = None
        self.udp_checksum = 0

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
        self.src_mac = format_mac(self.src_mac)
        self.dst_mac = format_mac(self.dst_mac)
        self.src_address = ipaddress.ip_address(self.src_address)
        self.dst_address = ipaddress.ip_address(self.dst_address)
        self.payload = data[42:]

    def pack(self):
        ip_hdr = bytearray(20)
        buffer = bytearray(
            ETHERNET_HEADER_LENGTH +
            IPV4_HEADER_LENGTH +
            UDP_HEADER_LENGTH +
            len(self.payload)
        )

        ihl = self.header_length | (self.version << 4)
        self.length = len(self.payload) + IPV4_HEADER_LENGTH + UDP_HEADER_LENGTH
        self.udp_length = len(self.payload) + UDP_HEADER_LENGTH

        struct.pack_into(
            ETHERNET_HEADER_FMT, buffer, 0,
            pack_mac(self.dst_mac), pack_mac(self.src_mac), self.ethertype
        )

        struct.pack_into(
            IPV4_HEADER_FMT, ip_hdr, 0, ihl,
            self.tos, self.length, self.identification, self.flags, self.ttl,
            self.protocol, self.header_checksum, self.src_address.packed, self.dst_address.packed
        )

        self.header_checksum = checksum(ip_hdr)

        struct.pack_into(
            IPV4_HEADER_FMT, buffer, 14, ihl,
            self.tos, self.length, self.identification, self.flags, self.ttl,
            self.protocol, self.header_checksum, self.src_address.packed, self.dst_address.packed
        )

        struct.pack_into(
            UDP_HEADER_FMT, buffer, 34,
            self.src_port, self.dst_port, self.udp_length, self.udp_checksum
        )

        buffer[42:] = self.payload
        return buffer

    def dump(self, f):
        print(self.__dict__, file=f)
