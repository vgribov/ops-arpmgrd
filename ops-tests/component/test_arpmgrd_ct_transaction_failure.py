# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.


from time import sleep
from pytest import mark

# Topology definition. the topology contains two back to back switches
# having four links between them.


TOPOLOGY = """
# +-------+    +-------+    +-------+
# |  hs1  <---->  sw2  <---->  hs2  |
# +-------+    +-------+    +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2

# Links
sw1:if01 -- hs1:eth0
sw1:if02 -- hs2:eth0
"""


# mac addresses for host 1 and host 2
mac1 = None
mac2 = None
# num of columns for 'show arp'/'show ipv6 neigh'
column_count = 4


def arp_manager_configure_and_setup(sw1, hs1, hs2, step):
    global mac1
    global mac2
    sw1._shells["bash"]._timeout=120
    # Configure switch sw1
    sw1("configure terminal")
    # Configure interface 1 on switch sw1
    sw1("interface 1")
    sw1("ip address 192.168.1.1/24")
    sw1("exit")
    # Configure interface 2 on switch sw1
    sw1("interface 2")
    sw1("ip address 192.168.2.1/24")
    sw1("exit")
    # Configure interface 3 on switch sw1
    sw1("interface 3")
    sw1("ip address 192.168.3.1/24")
    sw1("exit")
    # Configure interface 1
    sw1("/usr/bin/ovs-vsctl set interface 1 user_config:admin=up",
        shell='bash')
    # Configure interface 2
    sw1("/usr/bin/ovs-vsctl set interface 2 user_config:admin=up",
        shell='bash')
    # Configure interface 3
    sw1("/usr/bin/ovs-vsctl set interface 3 user_config:admin=up",
        shell='bash')
    ifconfig = hs1("ifconfig eth0")
    words = ifconfig.split()
    if "HWaddr" in words:
        mac1 = words[words.index("HWaddr") + 1]  # noqa
    else:
        mac1 = None  # noqa
    ifconfig = hs2("ifconfig eth0")
    words = ifconfig.split()
    if "HWaddr" in words:
        mac2 = words[words.index("HWaddr") + 1]  # noqa
    else:
        mac2 = None  # noqa
    # Configure host 1
    step("Configuring host 1 with 192.168.1.2/24\n")
    hs1.libs.ip.interface('eth0', addr='192.168.1.2/24', up=True)
    hs1.libs.ip.add_route("192.168.2.0/24", "192.168.1.1")
    # Configure host 2
    step("Configuring host 2 with 192.168.2.2/24\n")
    hs2.libs.ip.interface('eth0', addr='192.168.2.2/24', up=True)
    hs2.libs.ip.add_route("192.168.1.0/24", "192.168.2.1")
    # Ping from host 1 to switch
    step("Ping sw1 from hs1\n")
    ping = hs1.libs.ping.ping(2, "192.168.1.1")
    assert ping['transmitted'] is ping['received'] is 2
    # Ping from host 2 to switch
    step("Ping sw1 from hs2\n")
    ping = hs2.libs.ping.ping(2, "192.168.2.1")
    assert ping['transmitted'] is ping['received'] is 2
    # Ping from host 1 to host 2
    step("Ping hs2 from hs1\n")
    ping = hs1.libs.ping.ping(2, "192.168.2.2")
    assert ping['transmitted'] is ping['received'] is 2


def arp_manager_ovsdb_update(sw1, hs1, hs2, step):
    global mac1
    global mac2
    global column_count
    step("Test to verify arpmgr updates db with arp cache "
         "from kernel for directly connected hosts")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands
    # Show Neighbors
    step("Show neighbors\n")
    # workaround to get latest update call show twice,
    # needs to be fixed in CLI
    output = sw1("do show arp")
    rows = output.splitlines()
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
    assert words.index(
        max(words)) == max_index
    mac = words[mac_index]
    assert mac == mac2
    port = words[port_index]
    assert port == '2'
    state = words[state_index]
    assert state == 'reachable'


def arp_manager_ovsdb_failure_check_new_updates(sw1, hs1, hs2, step):
    step("Test to verify arpmgr updates db with arp cache "
         "from kernel for hosts which cannot be resolved")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands
    # Kill ovsdb to simulate a crash
    step("\nKilling ovsdb server\n")
    sw1("ip netns exec swns killall ovsdb-server", shell='bash')
    # Kill l3 portd so it does not add new ip address
    # on restart which will clear neighbors
    sw1("ip netns exec swns killall ops-portd", shell='bash')
    step("Adding 5 static arp entries before restarting ovsdb-server\n")
    # Add large number static arp entries
    # (not supported as functionality yet)
    # Just for CT purpose
    sw1("ip netns exec swns ip neigh add 192.168.1.101 "
        "lladdr 00:bb:cc:dd:ee:ff dev 1", shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.102 "
        "lladdr 00:bb:cc:dd:ee:ff dev 1", shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.103 "
        "lladdr 00:bb:cc:dd:ee:ff dev 1", shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.104 "
        "lladdr 00:bb:cc:dd:ee:ff dev 1", shell='bash')
    sw1("ip netns exec swns ip neigh add 192.168.1.105 "
        "lladdr 00:bb:cc:dd:ee:ff dev 1", shell='bash')
    # Delete ip on interface 2 so 192.168.2.2 entry gets deleted
    sw1("ip netns exec swns ip addr del 192.168.2.1/24 dev 2", shell='bash')
    # Delete host1 192.168.1.2 entry so its state goes to failed
    sw1("ip netns exec swns ip neigh del 192.168.1.2 dev 1", shell='bash')
    # Restart arpmgrd
    step("Restarting ovsdb-server\n")
    sw1("ip netns exec swns /usr/sbin/ovsdb-server "
        "--remote=punix:/var/run/openvswitch/db.sock "
        "--detach --no-chdir --pidfile -vSYSLOG:INFO "
        "/var/run/openvswitch/ovsdb.db /var/local/openvswitch/config.db",
        shell='bash')
    sleep(16)
    output = sw1("do show arp")
    rows = output.split("\n")
    static_entry1 = None
    static_entry2 = None
    static_entry3 = None
    static_entry4 = None
    static_entry5 = None
    host1v4 = None
    host2v4 = None
    for row in rows:
        if '192.168.1.101' in row:
            static_entry1 = row
        if '192.168.1.102' in row:
            static_entry2 = row
        if '192.168.1.103' in row:
            static_entry3 = row
        if '192.168.1.104' in row:
            static_entry4 = row
        if '192.168.1.105' in row:
            static_entry5 = row
        if '192.168.1.2' in row:
            host1v4 = row
        if '192.168.2.2' in row:
            host2v4 = row
    step("Verifying new static neighbors in ovsdb after ovsdb restart\n")
    assert static_entry1
    assert static_entry2
    assert static_entry3
    assert static_entry4
    assert static_entry5
    step("New entries verified in ovsdb after ovsdb restart\n")
    assert 'failed' in host1v4
    assert host2v4 is None


@mark.skipif(True, reason="Arp issue after restarting ovsdb server")
def test_arpmgrd_ct_transaction_failure(topology, step):
    sw1 = topology.get("sw1")
    assert sw1 is not None
    hs1 = topology.get("hs1")
    assert hs1 is not None
    hs2 = topology.get("hs2")
    assert hs2 is not None
    # Configure and setup to run test cases
    arp_manager_configure_and_setup(sw1, hs1, hs2, step)
    # Test for verifying arpmgr updates to db from kernel
    arp_manager_ovsdb_update(sw1, hs1, hs2, step)
    # Test for verifying arpmgr updates to db from kernel
    arp_manager_ovsdb_failure_check_new_updates(sw1, hs1, hs2, step)
