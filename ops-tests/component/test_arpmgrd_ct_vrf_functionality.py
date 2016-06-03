# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

import pytest
from time import sleep
from pytest import set_trace

TOPOLOGY = """
#
# +-------+                  +-------+
# |       |     +-------+    |       |
# |  hs1  <----->  sw1  <---->  hs2  |
# |       |     +-------+    |       |
# +-------+                  +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="host 1"] h1
[type=host name="host 2"] h2
[type=host name="host 3"] h3
[type=host name="host 4"] h4
[type=host name="host 5"] h5
[type=host name="host 6"] h6

# Links
sw1:if01 -- h1:if01
sw1:if02 -- h2:if01
sw1:if03 -- h3:if01
sw1:if04 -- h4:if01
sw1:if05 -- h5:if01
sw1:if06 -- h6:if01
"""

# mac addresses for host 1 and host 2
mac1 = None
mac2 = None
# num of columns for 'show arp'/'show ipv6 neigh'
column_count = 4


def arp_manager_configure_and_setup(sw1, h1, h2, h3, h4, h5, h6):

    global mac1
    global mac2
    sw1p1 = sw1.ports['if01']
    sw1p2 = sw1.ports['if02']
    sw1p3 = sw1.ports['if03']
    sw1p4 = sw1.ports['if04']
    sw1p5 = sw1.ports['if05']
    sw1p6 = sw1.ports['if06']
    h1p1 = h1.ports['if01']
    h2p1 = h2.ports['if01']
    h3p1 = h3.ports['if01']
    h4p1 = h4.ports['if01']
    h5p1 = h5.ports['if01']
    h6p1 = h6.ports['if01']

    sw1("configure terminal")
    sw1("vrf blue")
    sw1("vrf red")
    sw1("vrf green")
    #sw1("ip netns exec swns ip tuntap add dev 1 mode tap",
     #   shell='bash')

    sw1("configure terminal")
    # Configure interface 1 on switch s1
    sw1("interface {sw1p1}".format(**locals()))
    sw1("no shutdown")
    sw1("vrf attach blue" )
    sw1("ip address 192.168.1.1/24")
    sw1("ipv6 address 2000::1/120")

    # Configure interface 2 on switch s1
    sw1("interface {sw1p2}".format(**locals()))
    sw1("no shutdown")
    sw1("vrf attach blue" )
    sw1("ip address 192.168.2.1/24")
    sw1("ipv6 address 2002::1/120")

   # Configure interface 3 on switch s1
    sw1("interface {sw1p3}".format(**locals()))
    sw1("no shutdown")
    sw1("vrf attach red" )
    sw1("ip address 192.168.3.1/24")

  # Configure interface 4 on switch s1
    sw1("interface {sw1p4}".format(**locals()))
    sw1("no shutdown")
    sw1("vrf attach red" )
    sw1("ip address 192.168.4.1/24")

  # Configure interface 5 on switch s1
    sw1("interface {sw1p5}".format(**locals()))
    sw1("no shutdown")
    sw1("vrf attach green" )
    sw1("ip address 20.0.1.1/24")

  # Configure interface 6 on switch s1
    sw1("interface {sw1p6}".format(**locals()))
    sw1("no shutdown")
    sw1("vrf attach green" )
    sw1("ip address 20.0.2.1/24")
    sw1("end")

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
    print("Configuring host 1 with 192.168.1.2/24\n")
    h1.libs.ip.interface('if01', addr='192.168.1.2/24', up=True)
    h1("ip -4 route add 192.168.2.0/24 via 192.168.1.1")
    print("Configuring host 1 with 2000::2/120\n")
    h1.libs.ip.interface('if01', addr='2000::2/120', up=True)
    h1("ip -6 route add 2002::0/120 via 2000::1")

    # Configure host 2
    print("Configuring host 2 with 192.168.2.2/24\n")
    h2.libs.ip.interface('if01', addr='192.168.2.2/24', up=True)
    h2("ip -4 route add 192.168.1.0/24 via 192.168.2.1")
    print("Configuring host 2 with 2002::2/120\n")
    h2.libs.ip.interface('if01', addr='2002::2/120', up=True)
    h2("ip -6 route add 2000::0/120 via 2002::1")

     # Configure host 3
    print("Configuring host 3 with 192.168.3.2/24\n")
    h3.libs.ip.interface('if01', addr='192.168.3.2/24', up=True)
    h3("ip -4 route add 192.168.4.0/24 via 192.168.3.1")

    # Configure host 4
    print("Configuring host 4 with 192.168.4.2/24\n")
    h4.libs.ip.interface('if01', addr='192.168.4.2/24', up=True)
    h4("ip -4 route add 192.168.3.0/24 via 192.168.4.1")

     # Configure host 5
    print("Configuring host 5 with 20.0.1.2/24\n")
    h5.libs.ip.interface('if01', addr='20.0.1.2/24', up=True)
    h5("ip -4 route add 20.0.2.0/24 via 20.0.1.1")

    # Configure host 6
    print("Configuring host 6 with 20.0.2.2/24\n")
    h6.libs.ip.interface('if01', addr='20.0.2.2/24', up=True)
    h6("ip -4 route add 20.0.1.0/24 via 20.0.2.1")


    # Ping from host 1 to switch
    print("Ping s1 from h1\n")
    output = h1.libs.ping.ping(2, "192.168.1.1")
    assert output['transmitted'] == output['received']

    # Ping from host 2 to switch
    print("Ping s1 from h2\n")
    output = h2.libs.ping.ping(2, "192.168.2.1")
    assert output['transmitted'] == output['received']

    # Ping from host 1 to host 2
    print("Ping h2 from h1\n")
    output = h1.libs.ping.ping(2, "192.168.2.2")
    assert output['transmitted'] == output['received']

    # Ping from host 3 to switch
    print("Ping s1 from h3\n")
    output = h3.libs.ping.ping(2, "192.168.3.1")
    assert output['transmitted'] == output['received']

    # Ping from host 4 to switch
    print("Ping s1 from h4\n")
    output = h4.libs.ping.ping(2, "192.168.4.1")
    assert output['transmitted'] == output['received']

    # Ping from host 3 to host 4
    print("Ping h4 from h3\n")
    output = h3.libs.ping.ping(2, "192.168.4.2")
    assert output['transmitted'] == output['received']

    # Ping from host 5 to switch
    print("Ping s1 from h5\n")
    output = h5.libs.ping.ping(2, "20.0.1.1")
    assert output['transmitted'] == output['received']

    # Ping from host 6 to switch
    print("Ping s1 from h6\n")
    output = h6.libs.ping.ping(2, "20.0.2.1")
    assert output['transmitted'] == output['received']

    # Ping from host 5 to host 6
    print("Ping h6 from h5\n")
    output = h5.libs.ping.ping(2, "20.0.2.2")
    assert output['transmitted'] == output['received']

    # Ping from host 1 to switch
    print("IPv6 Ping s1 from h1\n")
    output = h1('ping6 -c 2 2000::1')
    assert "2 packets transmitted" and "2 received" and " 0% packet loss" in \
        output

    # Ping from host 2 to switch
    print("IPv6 Ping s1 from h2\n")
    output = h2('ping6 -c 2 2002::1')
    assert "2 packets transmitted" and "2 received" and " 0% packet loss" in \
        output

    sw1("sysctl -p /etc/sysctl.conf",
        shell='bash')

    # Ping from host 1 to host 2
    print("IPv6 Ping h2 from h1\n")
    output = h1('ping6 -c 2 2002::2')
    assert "2 packets transmitted" and "2 received" and " 0% packet loss" in \
        output

def arp_manager_ovsdb_update(sw1, h1, h2):
    print("\n### Test to verify arpmgr updates db "
          "with arp cache from kernel for directly connected hosts ###\n")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands
    # Show Neighbors
    print("Show neighbors\n")
    # workaround to get latest update call show twice, needs to be fixed in
    # CLI
    sleep(10)
    output = sw1("show arp vrf blue")
    output = sw1("show arp vrf blue")
    output = output + "\n" + sw1("show ipv6 neighbors vrf blue")
    print(output + "\n\n")

    rows = output.split('\n')
    host1v4 = None
    host1v6 = None
    host2v4 = None
    host2v6 = None

    mac_index = 1
    port_index = 2
    state_index = 3

    for row in rows:
        if '192.168.1.2' in row:
            host1v4 = row
        if '192.168.2.2' in row:
            host2v4 = row
        if '2000::2' in row:
            host1v6 = row
        if '2002::2' in row:
            host2v6 = row

    assert host1v4
    assert host2v4

    print("Host entries present in Neighbor table\n")
    max_index = column_count
    print("\nVerifying correct mac, port ,state and vrf in Neighbor table\n")
    words = host1v4.split()
    assert len(words) == max_index
    mac = words[mac_index]
    assert mac == mac1
    port = words[port_index]
    assert port == '1'
    state = words[state_index]
    assert state == 'reachable'

    words = host1v6.split()
    assert len(words) == max_index
    mac = words[mac_index]
    assert mac == mac1
    port = words[port_index]
    assert port == '1'
    state = words[state_index]
    assert state == 'reachable'

    words = host2v4.split()
    assert len(words) == max_index
    mac = words[mac_index]
    assert mac == mac2
    port = words[port_index]
    assert port == '2'
    state = words[state_index]
    assert state == 'reachable'

    words = host2v6.split()
    assert len(words) == max_index
    mac = words[mac_index]
    assert mac == mac2
    port = words[port_index]
    assert port == '2'
    state = words[state_index]
    assert state == 'reachable'

    print("Verified correct mac, port and state in Neighbor table\n\n")
    print("########## End of ovsdb update test ##########\n")


def arp_manager_neighbor_fail(sw1, h1, h2):
    print("\n### Test to verify arpmgr updates db "
          "with arp cache from kernel for hosts which cannot be "
          "resolved ###\n")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands

    print("Deleting ip address 192.168.1.2 on host 1\n")
    h1.libs.ip.remove_ip('if01', addr='192.168.1.2/24')
    print("Address deleted. Waiting for 45 seconds "
          "before checking Neighbor entries\n")
    # Wait minimum 45 seconds for us to reprobe
    # max index: No MAC word
    max_index = column_count - 1
    timer = 45
    # mac will be empty so port and state index will be 1 and 2
    # port_index = 1
    state_index = 2
    while timer > 0:
        sleep(20)
        output = sw1("show arp vrf blue")
        output = output + "\n" + sw1("show ipv6 neighbors vrf blue")

        rows = output.split('\n')
        host1v4 = None

        for row in rows:
            if '192.168.1.2' in row:
                host1v4 = row

        assert host1v4
        words = host1v4.split()
        if len(words) == max_index:
            timer = 0
        else:
            timer = timer - 5

    print(output + "\n")
    print("\nVerifying MAC addresses and state\n")
    assert len(words) == max_index
    state = words[state_index]
    assert state == 'failed'

    print("Verified failed state in Neighbor table\n\n")
    print("reset IP on host 1\n")
    h1.libs.ip.interface('if01', addr='192.168.1.2/24', up=True)
    h1("ip -4 route add 192.168.2.0/24 via 192.168.1.1")
    h1("ping 192.168.2.2 -c2")

    sleep(10)
    output = sw1("show arp vrf blue")
    output = output + "\n" + sw1("show ipv6 neighbors vrf blue")
    print(output + "\n\n")

    rows = output.split('\n')
    host1v4 = None
    mac_index = 1
    # port_index = 2
    state_index = 3
    for row in rows:
        if '192.168.1.2' in row:
            host1v4 = row

    assert host1v4
    max_index = column_count
    print("\nVerifying MAC addresses and state\n")
    words = host1v4.split()
    #assert words.index(max(words)) == max_index
    mac = words[mac_index]
    assert mac == mac1
    state = words[state_index]
    assert state == 'reachable'
    print("Host entry back to reachable state\n")
    print("########## End of unresolvable entry test ##########\n")


def arp_manager_dp_hit(sw1, h1, h2):
    print("\n########## Test to verify arpmgr checks dp hit bit ##########\n")
    print("### If dp hit is not set, let kernel stale out entry ###\n")
    print("### If dp hit is empty or true keep entry reachable by "
          "probing ###\n")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands

    json_cfg_dp_hit = "ovsdb-client transact '[ \"OpenSwitch\",\
        {\"op\" : \"update\", \"table\" : \"Neighbor\",\"where\":\
        [[\"ip_address\",\"==\",\"2000::2\"]],\"row\":{\"status\":\
        [\"map\",[[\"dp_hit\",\"false\"]]]}}]'"

    sw1(json_cfg_dp_hit, shell='bash')
    print("Configured dp hit to false for 2000::2. "
          "Entry should stale out within 45 seconds. Waiting.\n")

    max_index = column_count
    timer = 45
    host1v4 = None
    host1v6 = None
    host2v4 = None
    host2v6 = None

    state_index = 3
    while timer > 0:
        sleep(5)

        output = sw1("show arp vrf blue")
        output = output + "\n" + sw1("show ipv6 neighbors vrf blue")

        rows = output.split('\n')

        for row in rows:
            if '192.168.1.2' in row:
                host1v4 = row
            if '192.168.2.2' in row:
                host2v4 = row
            if '2000::2' in row:
                host1v6 = row
            if '2002::2' in row:
                host2v6 = row

        words = host1v6.split()
        assert len(words) == max_index
        state = words[state_index]
        if state == 'stale':
            timer = 0
        else:
            timer = timer - 5

    print(output + "\n\n")
    print("\nVerifying states of host. 2000::2 should be stale. "
          "The rest of entries should be reachable\n")
    words = host1v4.split()
    assert len(words) == max_index
    state = words[state_index]
    assert state == 'reachable'

    words = host1v6.split()
    assert len(words) == max_index
    state = words[state_index]
    assert state == 'stale'

    words = host2v4.split()
    assert len(words) == max_index
    state = words[state_index]
    assert state == 'reachable'

    words = host2v6.split()
    assert len(words) == max_index
    state = words[state_index]
    assert state == 'reachable'

    print("States verified \n\n")
    print("Reset host 1 dp_hit to true\n")

    json_cfg_dp_hit = "ovsdb-client transact '[ \"OpenSwitch\",\
        {\"op\" : \"update\",\"table\" : \"Neighbor\",\"where\":\
        [[\"ip_address\",\"==\",\"2000::2\"]],\"row\":{\"status\":\
        [\"map\",[[\"dp_hit\",\"true\"]]]}}]'"

    sw1(json_cfg_dp_hit, shell='bash')
    print("Configured dp hit to true for 2000::2. "
          "Entry should be reachable.\n")

    output = sw1("show arp vrf blue")
    output = output + "\n" + sw1("show ipv6 neighbors vrf blue")
    print(output + "\n\n")

    rows = output.split('\n')
    host1v6 = None

    for row in rows:
        if '2000::2' in row:
            host1v6 = row

    print("\nVerifying states of host. 2000::2 should be reachable.\n")
    max_index = column_count
    words = host1v6.split()
    assert len(words) == max_index
    state = words[state_index]
    assert state == 'reachable'

    print("2000::2 state is reachable\n")
    print("########## End of dp hit test ##########\n")


def arp_manager_neighbor_delete(sw1, h1, h2):
    sw1p2 = sw1.ports['if02']
    print("\n########## Test to verify arpmgr deletes row "
          "when kernel row gets deleted ##########\n")
    # configuring OpenSwitch, in the future it would be through
    # proper OpenSwitch commands

    # Change IP address of interface 2. This will delete 192.168.2.2 neighbor
    print("Configuring ip 1.1.1.1 on switch 1 interface 2\n")
    sw1('configure terminal')
    sw1("interface {sw1p2}".format(**locals()))
    sw1("no ip address 192.168.2.1/24")
    sw1("end")

    sleep(10)
    output = sw1("show arp vrf blue")
    output = output + "\n" + sw1("show ipv6 neighbors vrf blue")
    print(output + "\n\n")

    rows = output.split('\n')
    host2v4 = None

    for row in rows:
        if '192.168.2.2' in row:
            host2v4 = row
    assert host2v4 is None

    print("Neighbor 192.168.2.2 deleted\n")

    # configure 192.168.2.1 address back on switch interface 2,
    # ping from host 2
    # host 2 entry should be back

    print("Configuring ip 192.168.2.1 on switch 1\n")
    sw1('configure terminal')
    sw1("interface {sw1p2}".format(**locals()))
    sw1("ip address 192.168.2.1/24")
    sw1("end")

    #h2("ping 192.168.2.1 -c2")
    out = h2.libs.ping.ping(2, "192.168.2.1")
    assert out['transmitted'] == out['received']
    sleep (10)
    output = sw1("show arp vrf blue")
    output = output + "\n" + sw1("show ipv6 neighbors vrf blue")
    print(output + "\n\n")

    rows = output.split('\n')
    host2v4 = None

    for row in rows:
        if '192.168.2.2' in row:
            host2v4 = row
    assert host2v4
    print("Host 2 entry 192.168.2.2 entry back in neighbor table\n")
    print("########## End of delete entry test ##########\n")

@pytest.mark.skipif(True, reason="Disabling due to VRF macro not enabled")
def test_arp_manager_vrf_functionality(topology):
    sw1 = topology.get('sw1')
    h1 = topology.get('h1')
    h2 = topology.get('h2')
    h3 = topology.get('h3')
    h4 = topology.get('h4')
    h5 = topology.get('h5')
    h6 = topology.get('h6')
    assert sw1 is not None
    assert h1 is not None
    assert h2 is not None
    assert h3 is not None
    assert h4 is not None
    assert h5 is not None
    assert h6 is not None

    # Configure and setup to run test cases
    arp_manager_configure_and_setup(sw1, h1, h2, h3, h4, h5, h6)

    # Test for verifying arpmgr updates to db from kernel
    arp_manager_ovsdb_update(sw1, h1, h2)

    # Test for verifying arpmgr reprobe and updating failed neighbor state
    arp_manager_neighbor_fail(sw1, h1, h2)

    # Test for verifying arpmgr check dp hit to probe
    arp_manager_dp_hit(sw1, h1, h2)

    # Test for verifying arpmgr verify neighbor delete
    arp_manager_neighbor_delete(sw1, h1, h2)
