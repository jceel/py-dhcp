#
# Copyright 2015 iXsystems, Inc.
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
import logging
import socket
from .utils import format_mac
from .packet import Packet, PacketType, PacketOption, Option, MessageType


class Server(object):
    def __init__(self):
        self.sock = None
        self.address = None
        self.broadcast = None
        self.server_name = None
        self.port = 67
        self.leases = []
        self.requests = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.on_packet = None
        self.on_request = None
        self.handlers = {
            MessageType.DHCPDISCOVER: self.handle_discover,
            MessageType.DHCPREQUEST: self.handle_request,
            MessageType.DHCPRELEASE: self.handle_release
        }

    def start(self, address):
        if not self.server_name:
            raise RuntimeError('Please set server_name')

        if not self.on_request:
            raise RuntimeError('Please set on_request')

        if not isinstance(address, ipaddress.IPv4Interface):
            raise ValueError('address must be an instance of ipaddress.IPv4Interface')

        self.address = str(address.ip)
        self.broadcast = str(address.network.broadcast_address)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.port))

    def serve(self):
        while True:
            message, address = self.sock.recvfrom(2048)
            packet = Packet()
            packet.unpack(message)

            if self.on_packet:
                self.on_packet(packet)

            message_type = packet.find_option(PacketOption.MESSAGE_TYPE)
            if not message_type:
                self.logger.debug('Malformed packet: no MESSAGE_TYPE option')
                continue

            handler = self.handlers.get(message_type.value)
            if handler:
                handler(packet, address)

    def send_packet(self, packet, address):
        while True:
            try:
                self.sock.sendto(packet.pack(), address)
                return
            except InterruptedError:
                continue

    def handle_discover(self, packet, sender):
        offer = Packet()
        offer.clone_from(packet)
        offer.op = PacketType.BOOTREPLY
        offer.sname = self.server_name
        offer.options.append(Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPOFFER))

        hostname = packet.find_option(PacketOption.HOST_NAME)
        lease = self.on_request(format_mac(packet.chaddr), hostname.value if hostname else None)
        if not lease:
            # send NAK
            return

        self.requests[packet.xid] = lease
        offer.yiaddr = lease.client_ip
        offer.siaddr = ipaddress.ip_address(self.address)
        offer.options += lease.options
        self.send_packet(offer, (self.broadcast, 68))

    def handle_request(self, packet, sender):
        ack = Packet()
        ack.clone_from(packet)
        ack.op = PacketType.BOOTREPLY
        ack.htype = packet.htype
        ack.sname = self.server_name
        ack.options.append(Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPACK))

        hostname = packet.find_option(PacketOption.HOST_NAME)
        lease = self.requests.pop(packet.xid, None)
        if not lease:
            lease = self.on_request(format_mac(packet.chaddr), hostname.value if hostname else None)

        self.leases.append(lease)
        ack.yiaddr = lease.client_ip
        ack.siaddr = ipaddress.ip_address(self.address)
        ack.options += lease.options
        self.send_packet(ack, (self.broadcast, 68))

    def handle_release(self, packet):
        pass
