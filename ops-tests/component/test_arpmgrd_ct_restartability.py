# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from time import sleep

TOPOLOGY = """
#                   |-------------------|
# +-------+         |        +-------+  |  +-------+
# |       |     +---v---+    |       |  |  |       |
# |  hs1  <----->  sw1  <---->  hs2  |  |-->  hs3  |
# |       |     +-------+    |       |     |       |
# +-------+                  +-------+     +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="host 1"] h1
[type=host name="host 2"] h2
[type=host name="host 3"] h3

# Links
sw1:if01 -- h1:if01
sw1:if02 -- h2:if01
sw1:if03 -- h3:if01
"""


# mac addresses for host 1 and host 2
mac1 = None
mac2 = None
# num of columns for 'show arp'/'show ipv6 neigh'
column_count = 4


def test_arp_manager_configure_and_setup(topology, step):
    sw1 = topology.get('sw1')
    h1 = topology.get('h1')
    h2 = topology.get('h2')
    h3 = topology.get('h3')

    assert sw1 is not None
    assert h1 is not None
    assert h2 is not None
    assert h3 is not None

    sw1p1 = sw1.ports['if01']
    sw1p2 = sw1.ports['if02']
    sw1p3 = sw1.ports['if03']
    h1p1 = h1.ports['if01']
    h2p1 = h2.ports['if01']
    h3p1 = h3.ports['if01']

    # Configure switch s1
    sw1("configure terminal")

    # Configure interface 1 on switch s1
    sw1("interface {sw1p1}".format(**locals()))
    sw1("ip address 192.168.1.1/24")

    # Configure interface 2 on switch s1
    sw1("interface {sw1p2}".format(**locals()))
    sw1("ip address 192.168.2.1/24")

    # Configure interface 3 on switch s1
    sw1("interface {sw1p3}".format(**locals()))
    sw1("ip address 192.168.3.1/24")
    sw1("end")

    # Configure interface 1
    sw1("/usr/bin/ovs-vsctl set interface {sw1p1} "
        "user_config:admin=up".format(**locals()), shell='bash')

    # Configure interface 2
    sw1("/usr/bin/ovs-vsctl set interface {sw1p2} "
        "user_config:admin=up".format(**locals()), shell='bash')

    # Configure interface 3
    sw1("/usr/bin/ovs-vsctl set interface {sw1p3} "
        "user_config:admin=up".format(**locals()), shell='bash')

    ifconfig = h1("ifconfig {h1p1}".format(**locals()))
    words = ifconfig.split()
    if "HWaddr" in words:
        mac1 = words[words.index("HWaddr") + 1]
    else:
        mac1 = None

    ifconfig = h2("ifconfig {h2p1}".format(**locals()))
    words = ifconfig.split()
    if "HWaddr" in words:
        mac2 = words[words.index("HWaddr") + 1]
    else:
        mac2 = None

    # Configure host 1
    step("Configuring host 1 with 192.168.1.2/24\n")
    h1.libs.ip.interface('if01', addr='192.168.1.2/24', up=True)
    h1("ip -4 route add 192.168.2.0/24 via 192.168.1.1")

    # Configure host 2
    step("Configuring host 2 with 192.168.2.2/24\n")
    h2.libs.ip.interface('if01', addr='192.168.2.2/24', up=True)
    h2("ip -4 route add 192.168.1.0/24 via 192.168.2.1")

    # Ping from host 1 to switch
    step("Ping s1 from h1\n")
    out = h1.libs.ping.ping(2, "192.168.1.1")
    assert out['transmitted'] == out['received']

    # Ping from host 2 to switch
    step("Ping s1 from h2\n")
    out = h2.libs.ping.ping(2, "192.168.2.1")
    assert out['transmitted'] == out['received']

    # Ping from host 1 to host 2
    step("Ping h2 from h1\n")
    out = h1.libs.ping.ping(2, "192.168.2.2")
    assert out['transmitted'] == out['received']

    step("\n########## Test to verify arpmgr updates db with arp cache"
         " from kernel for directly connected hosts ##########\n")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands

    # Show Neighbors
    step("Show neighbors\n")
    output = sw1("show arp")

    rows = output.split('\n')
    host1v4 = None
    host2v4 = None

    mac_index = 1
    port_index = 2
    state_index = 3

    for row in rows:
        if '192.168.1.2' in row:
            host1v4 = row
        if '192.168.2.2' in row:
            host2v4 = row

    assert host1v4
    assert host2v4

    step("Host entries present in Neighbor table\n")
    max_index = column_count - 1
    step("\nVerifying correct mac, port and state in Neighbor table\n")
    words = host1v4.split()
    assert words.index(max(words)) == max_index
    mac = words[mac_index]
    assert mac == mac1
    port = words[port_index]
    assert port == '1'
    state = words[state_index]
    assert state == 'reachable'

    words = host2v4.split()
    assert words.index(max(words)) == max_index
    mac = words[mac_index]
    assert mac == mac2
    port = words[port_index]
    assert port == '2'
    state = words[state_index]
    assert state == 'reachable'

    step("\n########## Test to verify arpmgr updates db with arp cache "
         "from kernel for hosts which cannot be resolved ##########\n")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands

    # Kill arpmgrd to simulate a crash
    step("\nKilling arpmgrd\n")
    sw1("ip netns exec swns killall ops-arpmgrd", shell='bash')

    # Configure host 3
    step("Configuring host 3 with 192.168.3.2/24\n")
    h3.libs.ip.interface('if01', addr='192.168.3.2/24', up=True)
    h3("ip -4 route add default via 192.168.3.1")

    # Ping from host 3 to switch
    step("Ping s1 from h3\n")
    out = h3.libs.ping.ping(2, "192.168.3.1")
    assert out['transmitted'] == out['received']

    step("Also adding 50 static arp entries before restarting arpmgrd\n")
    # Add large number static arp entries
    # (not supported as functionality yet)
    # Just for CT purpose
    sw1("ip netns exec swns ip neigh add 192.168.1.101 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.102 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.103 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.104 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.105 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.106 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.107 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.108 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.109 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.110 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.111 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.112 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.113 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.114 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.115 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.116 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.117 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.118 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.119 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.120 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.121 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.122 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.123 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.124 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.125 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.126 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.127 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.128 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.129 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.130 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.131 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.132 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.133 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.134 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.135 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.136 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.137 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.138 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.139 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.140 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.141 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.142 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.143 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.144 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.145 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.146 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.147 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.148 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.149 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.150 \
        lladdr 00:bb:cc:dd:ee:ff dev {sw1p1}".format(**locals()),
        shell='bash')

    step("Arpmgrd not yet started. show arp output\n")
    output = sw1("show arp")

    # Restart arpmgrd
    step("Restarting arpmgrd\n")
    sw1("ip netns exec swns ops-arpmgrd --pidfile --detach", shell='bash')

    sleep(5)
    output = sw1("show arp")
    rows = output.split("\n")
    rowcount = len(rows) - 3
    output = output + "\n" + sw1("show ipv6 neighbors")
    step(output + "\n\n")
    assert rowcount == 53
    step("New entries added to db after arpmgrd restart")

    # kill arpmgrd
    step("\nKilling arpmgrd\n")
    sw1("ip netns exec swns killall ops-arpmgrd", shell='bash')

    # reconfigure interface 1
    sw1("config t")
    sw1("interface {sw1p1}".format(**locals()))
    sw1("no ip address 192.168.1.1/24")
    sw1("end")

    # delete ip on s1 so its state changes to failed
    sw1("ip netns exec swns ip neigh del 192.168.2.2 dev \
        {sw1p2}".format(**locals()), shell='bash')

    # All the neighbor entries should have been deleted
    step("Arpmgrd not yet started. show arp output\n")
    output = sw1("show arp")

    # Restart arpmgrd
    step("Restarting arpmgrd\n")
    sw1("ip netns exec swns ops-arpmgrd --pidfile --detach", shell='bash')

    sleep(10)
    output = sw1("show arp")
    rows = output.split("\n")
    rowcount = len(rows) - 3
    assert rowcount == 2

    host2v4 = None
    for row in rows:
        if '192.168.2.2' in row:
            host2v4 = row
    assert 'failed' in host2v4
