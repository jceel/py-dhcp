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
from datetime import datetime, timedelta
from .packet import Option, PacketOption


class Lease(object):
    def __init__(self):
        self.started_at = datetime.utcnow()
        self.client_mac = None
        self.client_ip = None
        self.client_mask = None
        self.lifetime = 86400
        self.router = None
        self.host_name = None
        self.domain_name = None
        self.dns_addresses = []
        self.dns_search = []
        self.static_routes = []
        self.active = False

    def __getstate__(self):
        return {
            'client_mac': self.client_mac,
            'client_ip': str(self.client_ip),
            'client_mask': str(self.client_mask),
            'lifetime': self.lifetime,
            'router': str(self.router) if self.router else None,
            'dns_addresses': [str(i) for i in self.dns_addresses],
            'active': self.active
        }

    @property
    def client_interface(self):
        return ipaddress.ip_interface('{0}/{1}'.format(self.client_ip, self.client_mask))

    @property
    def ends_at(self):
        return self.started_at + timedelta(seconds=self.lifetime)

    @property
    def options(self):
        yield Option(PacketOption.LEASE_TIME, self.lifetime)
        yield Option(PacketOption.SUBNET_MASK, self.client_mask)

        if self.router:
            yield Option(PacketOption.ROUTER, self.router)

        if self.dns_addresses:
            yield Option(PacketOption.DOMAIN_NAME_SERVER, self.dns_addresses)

        if self.static_routes:
            yield Option(PacketOption.STATIC_ROUTES, self.static_routes)
