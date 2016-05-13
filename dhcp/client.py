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
import time
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
        self.discover_thread = None
        self.t1_timer = None
        self.t2_timer = None
        self.client_ident = client_ident
        self.lease = None
        self.requested_address = None
        self.server_address = None
        self.cv = threading.Condition()
        self.state = State.INIT
        self.on_state_change = lambda state: None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.port))
        self.listen_thread = threading.Thread(target=self.__listen, daemon=True, name='py-dhcp listen thread')
        self.listen_thread.start()

    def __t1(self):
        """
        T1 aka renew timer
        """
        self.logger.debug('Renewing IP address lease')
        with self.cv:
            self.state = State.RENEWING

        self.renew()

    def __t2(self):
        """
        T2 aka rebind timer
        """
        self.logger.debug('Renew timed out; rebinding')
        with self.cv:
            self.server_address = None
            self.state = State.REBINDING

        self.discover()
        self.request()

    def __listen(self):
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
                    self.logger.debug('DHCPOFFER received and ignored')
                    continue

                self.logger.debug('DHCP server is {0}'.format(packet.siaddr))
                with self.cv:
                    self.server_address = packet.siaddr
                    self.requested_address = packet.yiaddr
                    self.state = State.REQUESTING
                    self.on_state_change(self.state)
                    self.cv.notify_all()

            if opt.value == MessageType.DHCPACK:
                if self.state not in (State.REQUESTING, State.RENEWING, State.REBINDING):
                    self.logger.debug('DHCPACK received and ignored')
                    continue

                lease = Lease()
                lease.client_ip = packet.yiaddr
                lease.client_mac = self.hwaddr

                for opt in packet.options:
                    if opt.id == PacketOption.LEASE_TIME:
                        lease.lifetime = 5 # opt.value

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

                # (re)start T1 and T2 timers
                if self.t1_timer:
                    self.t1_timer.cancel()
                self.t1_timer = threading.Timer(lease.lifetime / 2, self.__t1)
                self.t1_timer.start()

                if self.t2_timer:
                    self.t2_timer.cancel()
                self.t2_timer = threading.Timer(lease.lifetime, self.__t2)
                self.t2_timer.start()

                self.logger.debug('Bound to {0}'.format(lease.client_ip))

                with self.cv:
                    self.lease = lease
                    self.state = State.BOUND
                    self.on_state_change(self.state)
                    self.cv.notify_all()

            if opt.value == MessageType.DHCPNAK:
                self.logger.warning('DHCP server declined out request')

    def __discover(self, requested_address=None):
        with self.cv:
            self.state = State.SELECTING
            self.on_state_change(self.state)
            self.cv.notify_all()

        packet = Packet()
        packet.op = PacketType.BOOTREQUEST
        packet.xid = random.randint(0, 2**32 - 1)
        packet.chaddr = pack_mac(self.hwaddr)
        packet.options = [
            Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPDISCOVER)
        ]

        if requested_address:
            packet.options.append(Option(PacketOption.REQUESTED_IP, self.requested_address))

        retries = 0

        while True:
            self.logger.debug('Sending DHCPDISCOVER')
            try:
                self.sock.sendto(packet.pack(), ('255.255.255.255', 67))
            except OSError as err:
                self.logger.debug('Cannot send message: {0}'.format(str(err)))
            with self.cv:
                if self.cv.wait_for(lambda: self.state == State.REQUESTING, 5 if retries < 10 else 30):
                    return

    def discover(self, block=True, timeout=None):
        self.discover_thread = threading.Thread(
            target=self.__discover,
            args=(self.requested_address,),
            daemon=True,
            name='py-dhcp discover thread'
        )

        self.discover_thread.start()

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
            try:
                self.sock.sendto(packet.pack(), (str(self.server_address), 67))
            except OSError as err:
                self.logger.debug('Cannot send message: {0}'.format(str(err)))

            if block:
                self.cv.wait_for(lambda: self.state == State.BOUND, timeout)
                return self.lease

    def renew(self, block=True, timeout=None):
        self.request()

    def release(self):
        pass

    def cancel(self):
        with self.cv:
            if self.state in (State.SELECTING, State.REBINDING):
                pass