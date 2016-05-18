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
import random
import threading
import logging
import netif
from bsd import bpf
from .packet import Packet, Option, PacketOption, PacketType, MessageType
from .udp import UDPPacket
from .lease import Lease
from .utils import pack_mac


BPF_PROGRAM = [
    bpf.Statement(bpf.InstructionClass.LD | bpf.OperandSize.H | bpf.OperandMode.ABS, 36),
    bpf.Jump(bpf.InstructionClass.JMP | bpf.Opcode.JEQ | bpf.Source.K, 68, 0, 5),
    bpf.Statement(bpf.InstructionClass.LD | bpf.OperandSize.B | bpf.OperandMode.ABS, 23),
    bpf.Jump(bpf.InstructionClass.JMP | bpf.Opcode.JEQ | bpf.Source.K, 0x11, 0, 3),
    bpf.Statement(bpf.InstructionClass.LD | bpf.OperandSize.H | bpf.OperandMode.ABS, 12),
    bpf.Jump(bpf.InstructionClass.JMP | bpf.Opcode.JEQ | bpf.Source.K, 0x0800, 0, 1),
    bpf.Statement(bpf.InstructionClass.RET | bpf.Source.K, 0x0fffffff),
    bpf.Statement(bpf.InstructionClass.RET | bpf.Source.K, 0)
]


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
    def __init__(self, interface, hostname=''):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.interface = interface
        self.bpf = None
        self.port = 68
        self.default_lifetime = 300
        self.listen_thread = None
        self.discover_thread = None
        self.t1_timer = None
        self.t2_timer = None
        self.client_ident = None
        self.hostname = hostname
        self.lease = None
        self.requested_address = None
        self.server_mac = None
        self.server_address = None
        self.server_name = None
        self.cv = threading.Condition()
        self.state = State.INIT
        self.xid = None
        self.on_bind = lambda lease: None
        self.on_unbind = lambda lease: None
        self.on_state_change = lambda state: None
        self.source_if = netif.get_interface(self.interface)
        self.hwaddr = str(self.source_if.link_address.address)

    def start(self):
        self.logger.info('Starting')
        self.bpf = bpf.BPF()
        self.bpf.open()
        self.bpf.immediate = True
        self.bpf.interface = self.interface
        self.bpf.apply_filter(BPF_PROGRAM)
        self.listen_thread = threading.Thread(target=self.__listen, daemon=True, name='py-dhcp listen thread')
        self.listen_thread.start()
        self.discover(False)

    def __getstate__(self):
        return {
            'state': self.state.name,
            'server_address': self.server_address,
            'server_name': self.server_name,
            'lease_starts_at': self.lease.started_at if self.lease else None,
            'lease_end_at': None
        }

    def __setstate(self, state):
        self.state = state
        self.on_state_change(state)
        self.cv.notify_all()

    def __t1(self):
        """
        T1 aka renew timer
        """
        self.logger.debug('Renewing IP address lease')
        with self.cv:
            self.__setstate(State.RENEWING)

        self.renew()

    def __t2(self):
        """
        T2 aka rebind timer
        """
        self.logger.debug('Renew timed out; rebinding')
        with self.cv:
            self.lease = None
            self.server_address = None
            self.__setstate(State.REBINDING)

        self.discover()

    def __send(self, mac, src_ip, dst_ip, payload):
        udp = UDPPacket(
            src_mac=self.hwaddr, dst_mac=mac, src_address=ipaddress.ip_address(src_ip),
            dst_address=ipaddress.ip_address(dst_ip), src_port=68, dst_port=67,
            payload=payload
        )

        self.bpf.write(udp.pack())

    def __listen(self):
        for buf in self.bpf.read():
            udp = UDPPacket()
            udp.unpack(buf)

            if udp.dst_port != 68 and udp.src_port != 67:
                continue

            packet = Packet()
            packet.unpack(udp.payload)

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
                    self.server_mac = udp.src_mac
                    self.server_address = udp.src_address
                    self.requested_address = packet.yiaddr
                    self.__setstate(State.REQUESTING)
                    self.request(False)

            if opt.value == MessageType.DHCPACK:
                if self.state not in (State.REQUESTING, State.RENEWING, State.REBINDING):
                    self.logger.debug('DHCPACK received and ignored')
                    continue

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

                lease.lifetime = 10

                # (re)start T1 and T2 timers
                if self.t1_timer:
                    self.t1_timer.cancel()
                self.t1_timer = threading.Timer(lease.lifetime / 2, self.__t1)
                self.t1_timer.start()

                if self.t2_timer:
                    self.t2_timer.cancel()
                self.t2_timer = threading.Timer(lease.lifetime, self.__t2)
                self.t2_timer.start()

                self.on_bind(lease)
                self.logger.debug('Bound to {0}'.format(lease.client_ip))

                with self.cv:
                    self.lease = lease
                    self.server_name = packet.sname
                    self.__setstate(State.BOUND)

            if opt.value == MessageType.DHCPNAK:
                self.logger.warning('DHCP server declined out request')

    def __discover(self, requested_address=None):
        with self.cv:
            self.__setstate(State.SELECTING)

        self.xid = random.randint(0, 2**32 - 1)
        packet = Packet()
        packet.op = PacketType.BOOTREQUEST
        packet.xid = self.xid
        packet.chaddr = pack_mac(self.hwaddr)
        packet.options = [
            Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPDISCOVER),
            Option(PacketOption.CLIENT_IDENT, pack_mac(self.hwaddr)),
            Option(PacketOption.HOST_NAME, self.hostname)
        ]

        if requested_address:
            packet.options.append(Option(PacketOption.REQUESTED_IP, self.requested_address))

        retries = 0

        while True:
            self.logger.debug('Sending DHCPDISCOVER')
            try:
                self.__send('FF:FF:FF:FF:FF:FF', '0.0.0.0', '255.255.255.255', packet.pack())
            except OSError as err:
                self.logger.debug('Cannot send message: {0}'.format(str(err)))

            with self.cv:
                if self.cv.wait_for(lambda: self.state == State.REQUESTING, 5 if retries < 10 else 30):
                    return

                retries += 1

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
                self.cv.wait_for(lambda: self.state == State.BOUND, timeout)
                return self.lease

    def request(self, block=True, timeout=None):
        packet = Packet()
        packet.op = PacketType.BOOTREQUEST
        packet.xid = self.xid
        packet.chaddr = pack_mac(self.hwaddr)
        packet.siaddr = int(self.server_address)
        packet.options = [
            Option(PacketOption.MESSAGE_TYPE, MessageType.DHCPREQUEST),
            Option(PacketOption.REQUESTED_IP, self.requested_address),
            Option(PacketOption.HOST_NAME, self.hostname),
            Option(PacketOption.CLIENT_IDENT, pack_mac(self.hwaddr))
        ]

        with self.cv:
            try:
                self.logger.debug('Sending DHCPREQUEST')
                self.__send('FF:FF:FF:FF:FF:FF', '0.0.0.0', self.server_address, packet.pack())
            except OSError as err:
                self.logger.debug('Cannot send message: {0}'.format(str(err)))

            if block:
                self.cv.wait_for(lambda: self.state == State.BOUND, timeout)
                return self.lease

    def wait_for_bind(self, timeout=None):
        with self.cv:
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