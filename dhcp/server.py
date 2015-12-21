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

import logging
import socket
from .packet import Packet, PacketOption, MessageType


class Lease(object):
    def __init__(self, server):
        self.server = server
        self.client_mac = None
        self.client_ip = None
        self.lifetime = None


class Server(object):
    def __init__(self):
        self.sock = None
        self.address = None
        self.port = 67
        self.leases = []
        self.logger = logging.getLogger(self.__class__.__name__)
        self.on_packet = None
        self.on_request = None
        self.handlers = {
            MessageType.DHCPDISCOVER: self.handle_discover,
            MessageType.DHCPREQUEST: self.handle_request,
            MessageType.DHCPRELEASE: self.handle_release
        }

    def start(self, address):
        self.address = address
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind((self.address, self.port))

    def serve(self):
        while True:
            message, address = self.sock.recvfrom(2048)
            packet = Packet()
            packet.unpack(message)

            if self.on_packet:
                self.on_packet(packet)

            if PacketOption.MESSAGE_TYPE not in packet.options:
                self.logger.debug('Malformed packet: no MESSAGE_TYPE option')
                continue

            message_type = packet.options[PacketOption.MESSAGE_TYPE]
            handler = self.handlers.get(message_type)
            if handler:
                handler(packet)

    def send_packet(self, packet, address):
        while True:
            try:
                self.sock.sendto(packet.pack(), address)
                return
            except InterruptedError:
                continue

    def handle_discover(self, packet):
        pass

    def handle_request(self, packet):
        pass

    def handle_release(self, packet):
        pass
