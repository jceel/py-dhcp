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

import sys
import ipaddress
import enum
import random
import socket
import threading
import logging
from .packet import Packet, Option, PacketOption, PacketType, MessageType
from .lease import Lease
from .utils import pack_mac


class State(enum.Enum):
    INIT = 1
    SELECTING = 2
    REQUESTING = 3
    INIT_REBOOT = 4
    REBOOTING = 5
    BOUND = 6
    RENEWING = 7
    REBINDING = 8


class Client(object):
    def __init__(self, hwaddr, client_ident=''):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.hwaddr = hwaddr
        self.sock = None
        self.port = 68
        self.default_lifetime = 300
        self.listen_thread = None
        self.client_ident = client_ident
        self.lease = None
        self.requested_address = None
        self.server_address = None
        self.cv = threading.Condition()
        self.state = State.INIT

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.port))
        self.listen_thread = threading.Thread(target=self.listen, daemon=True, name='DHCP client thread')
        self.listen_thread.start()

    def listen(self):
        while True:
            message, address = self.sock.recvfrom(2048)
            packet = Packet()
            packet.unpack(message)

            opt = packet.find_option(PacketOption.MESSAGE_TYPE)
            if not opt:
                self.logger.warning('Received DHCP packet without message type, discarding')
                continue

            self.logger.debug('Received DHCP packet of type {0}'.format(opt.value.name))

            if opt.value == MessageType.DHCPOFFER:
                if self.state != State.SELECTING:
                    pass

                self.logger.debug('DHCP server is {0}'.format(packet.siaddr))
                with self.cv:
                    self.server_address = packet.siaddr
                    self.requested_address = packet.yiaddr
                    self.state = State.REQUESTING
                    self.cv.notify_all()

            if opt.value == MessageType.DHCPACK:
                if self.state not in (State.REQUESTING, State.RENEWING, State.REBINDING):
                    pass

                lease = Lease()
                lease.client_ip = packet.yiaddr
                lease.client_mac = self.hwaddr

                for opt in packet.options:
                    if opt.id == PacketOption.LEASE_TIME:
                        lease.lifetime = opt.value

                    if opt.id == PacketOption.SUBNET_MASK:
                        lease.client_mask = opt.value

                    if opt.id == PacketOption.ROUTER:
                        lease.router = opt.value

                    if opt.id == PacketOption.DOMAIN_NAME:
                        lease.domain_name = opt.value

                    if opt.id == PacketOption.DOMAIN_NAME_SERVER:
                        lease.dns_addresses = opt.value

                    if opt.id == PacketOption.STATIC_ROUTES:
                        lease.static_routes = opt.value

                    if opt.id == PacketOption.HOST_NAME:
                        lease.host_name = opt.value

                self.logger.debug('Bound to {0}'.format(lease.client_ip))

                with self.cv:
                    self.lease = lease
                    self.state = State.BOUND
                    self.cv.notify_all()

            if opt.value == MessageType.DHCPNAK:
                self.logger.warning('DHCP server declined out request')

    def discover(self, block=True, timeout=None):
        packet = Packet()
        packet.op = PacketType.BOOTREQUEST
        packet.xid = random.randint(0, 2**32 - 1)
        packet.chaddr = pack_mac(self.hwaddr)
        packet.options = [
            Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPDISCOVER)
        ]

        if self.requested_address:
            packet.options.append(Option(PacketOption.REQUESTED_IP, self.requested_address))

        with self.cv:
            self.sock.sendto(packet.pack(), ('255.255.255.255', 67))
            self.state = State.SELECTING
            self.cv.notify_all()

        if block:
            with self.cv:
                self.cv.wait_for(lambda: self.state == State.REQUESTING, timeout)

    def request(self, block=True, timeout=None):
        packet = Packet()
        packet.op = PacketType.BOOTREQUEST
        packet.xid = random.randint(0, 2**32 - 1)
        packet.chaddr = pack_mac(self.hwaddr)
        packet.siaddr = self.server_address
        packet.options = [
            Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPREQUEST),
            Option(PacketOption.REQUESTED_IP, self.requested_address),
            Option(PacketOption.CLASS_IDENT, self.client_ident)
        ]

        with self.cv:
            self.sock.sendto(packet.pack(), (str(self.server_address), 67))
            if block:
                self.cv.wait_for(lambda: self.state == State.BOUND, timeout)
                return self.lease

    def release(self):
        pass