#!/usr/bin/python

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

import pytest
from opsvsi.docker import *
from opsvsi.opsvsitest import *
from opsvsiutils.systemutil import *


class arpManagerFunctionalityTests(OpsVsiTest):
    # mac addresses for host 1 and host 2
    mac1 = None
    mac2 = None
    # num of columns for 'show arp'/'show ipv6 neigh'
    column_count = 4

    def setupNet(self):
        # if you override this function, make sure to
        # either pass getNodeOpts() into hopts/sopts of the topology that
        # you build or into addHost/addSwitch calls
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        arpmgrd_topo = SingleSwitchTopo(
            k=2, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(arpmgrd_topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)

    def arp_manager_configure_and_setup(self):
        s1 = self.net.switches[0]
        h1 = self.net.hosts[0]
        h2 = self.net.hosts[1]
        # Configure switch s1
        s1.cmdCLI("configure terminal")

        # Configure interface 1 on switch s1
        s1.cmdCLI("interface 1")
        s1.cmdCLI("ip address 192.168.1.1/24")
        s1.cmdCLI("ipv6 address 2000::1/120")
        s1.cmdCLI("exit")

        # Configure interface 2 on switch s1
        s1.cmdCLI("interface 2")
        s1.cmdCLI("ip address 192.168.2.1/24")
        s1.cmdCLI("ipv6 address 2002::1/120")
        s1.cmdCLI("exit")

        # Configure interface 1
        s1.ovscmd("/usr/bin/ovs-vsctl set interface 1 user_config:admin=up")

        # Configure interface 2
        s1.ovscmd("/usr/bin/ovs-vsctl set interface 2 user_config:admin=up")

        ifconfig = h1.cmd("ifconfig h1-eth0")
        words = ifconfig.split()
        if "HWaddr" in words:
            self.mac1 = words[words.index("HWaddr") + 1]
        else:
            self.mac1 = None

        ifconfig = h2.cmd("ifconfig h2-eth0")
        words = ifconfig.split()
        if "HWaddr" in words:
            self.mac2 = words[words.index("HWaddr") + 1]
        else:
            self.mac2 = None

        # Configure host 1
        info("Configuring host 1 with 192.168.1.2/24\n")
        h1.cmd("ip addr add 192.168.1.2/24 dev h1-eth0")
        h1.cmd("ip route add 192.168.2.0/24 via 192.168.1.1")
        info("Configuring host 1 with 2000::2/120\n")
        h1.cmd("ip addr add 2000::2/120 dev h1-eth0")
        h1.cmd("ip route add 2002::0/120 via 2000::1")

        # Configure host 2
        info("Configuring host 2 with 192.168.2.2/24\n")
        h2.cmd("ip addr add 192.168.2.2/24 dev h2-eth0")
        h2.cmd("ip route add 192.168.1.0/24 via 192.168.2.1")
        info("Configuring host 2 with 2002::2/120\n")
        h2.cmd("ip addr add 2002::2/120 dev h2-eth0")
        h2.cmd("ip route add 2000::0/120 via 2002::1")

        # Ping from host 1 to switch
        info("Ping s1 from h1\n")
        output = h1.cmd("ping 192.168.1.1 -c2")
        status = parsePing(output)
        assert status, "Ping Failed\n"
        info("Ping Success\n")

        # Ping from host 2 to switch
        info("Ping s1 from h2\n")
        output = h2.cmd("ping 192.168.2.1 -c2")
        status = parsePing(output)
        assert status, "Ping Failed"
        info("Ping Success\n")

        # Ping from host 1 to host 2
        info("Ping h2 from h1\n")
        output = h1.cmd("ping 192.168.2.2 -c2")
        status = parsePing(output)
        assert status, "Ping Failed"
        info("Ping Success\n")

        # Ping from host 1 to switch
        info("IPv6 Ping s1 from h1\n")
        output = h1.cmd("ping6 2000::1 -c2")
        status = parsePing(output)
        assert status, "Ping Failed"
        info("Ping Success\n")

        # Ping from host 2 to switch
        info("IPv6 Ping s1 from h2\n")
        output = h2.cmd("ping6 2002::1 -c2")
        status = parsePing(output)
        assert status, "Ping Failed"
        info("Ping Success\n")

        # Ping from host 1 to host 2
        info("IPv6 Ping h2 from h1\n")
        output = h1.cmd("ping6 2002::2 -c2")
        status = parsePing(output)
        assert status, "Ping Failed"
        info("Ping Success\n")

    def arp_manager_ovsdb_update(self):
        info("\n########## Test to verify arpmgr updates db "
             "with arp cache from kernel for directly "
             "connected hosts ##########\n")
        # configuring OpenSwitch, in the future it would be through
        # proper OpenSwitch commands
        s1 = self.net.switches[0]
        h1 = self.net.hosts[0]
        h2 = self.net.hosts[1]
        output1 = s1.cmd("ip netns exec swns ip neigh show")
        info(output1 + "\n\n")
        time.sleep(3)
        # Show Neighbors
        info("Show neighbors\n")
        # workaround to get latest update call show twice, needs to be fixed in
        # CLI
        output = s1.cmdCLI("do show arp")
        output = s1.cmdCLI("do show arp")
        output = output + "\n" + s1.cmdCLI("do show ipv6 neighbors")
        info(output + "\n\n")

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

        assert host1v4, "host 1 IPv4 not in neighbor table"
        #assert host1v6, "host 1 IPv6 not in neighbor table"
        assert host2v4, "host 2 IPv4 not in neighbor table"
        #assert host2v6, "host 2 IPv6 not in neighbor table"

        info("Host entries present in Neighbor table\n")
        max_index = self.column_count - 1
        info("\nVerifying correct mac, port and state in Neighbor table\n")
        words = host1v4.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        mac = words[mac_index]
        assert mac == self.mac1, "Incorrect host1 MAC address"
        port = words[port_index]
        assert port == '1', "Incorrect port"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        words = host1v6.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        mac = words[mac_index]
        assert mac == self.mac1, "Incorrect host1 MAC address"
        port = words[port_index]
        assert port == '1', "Incorrect port"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        words = host2v4.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        mac = words[mac_index]
        assert mac == self.mac2, "Incorrect host2 MAC address"
        port = words[port_index]
        assert port == '2', "Incorrect port"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        words = host2v6.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        mac = words[mac_index]
        assert mac == self.mac2, "Incorrect host2 MAC address"
        port = words[port_index]
        assert port == '2', "Incorrect port"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        info("Verified correct mac, port and state in Neighbor table\n\n")

        info("########## End of ovsdb update test ##########\n")

    def arp_manager_neighbor_fail(self):
        info("\n########## Test to verify arpmgr updates db "
             "with arp cache from kernel for hosts "
             "which cannot be resolved ##########\n")
        # configuring OpenSwitch, in the future it would be through
        # proper OpenSwitch commands
        s1 = self.net.switches[0]
        h1 = self.net.hosts[0]
        h2 = self.net.hosts[1]

        info("Deleting ip address 192.168.1.2 on host 1\n")
        h1.cmd("ip addr del 192.168.1.2/24 dev h1-eth0")
        info("Address deleted. Waiting for 45 seconds "
             "before checking Neighbor entries\n")
        # Wait minimum 45 seconds for us to reprobe
        # max index: No MAC word
        max_index = self.column_count - 1 - 1
        timer = 45
        # mac will be empty so port and state index will be 1 and 2
        port_index = 1
        state_index = 2
        while timer > 0:
            time.sleep(5)
            output = s1.cmdCLI("do show arp")
            output = output + "\n" + s1.cmdCLI("do show ipv6 neighbors")

            rows = output.split('\n')
            host1v4 = None

            for row in rows:
                if '192.168.1.2' in row:
                    host1v4 = row

            assert host1v4, "host 1 IPv4 not in neighbor table"
            words = host1v4.split()
            if words.index(max(words)) == max_index:
                timer = 0
            else:
                timer = timer - 5

        info(output + "\n")
        info("\nVerifying MAC addresses and state\n")
        assert words.index(
            max(words)) == max_index, "MAC address still present"
        state = words[state_index]
        assert state == 'failed', "State incorrect, should be failed"

        info("Verified failed state in Neighbor table\n\n")
        info("reset IP on host 1\n")
        h1.cmd("ip addr add 192.168.1.2/24 dev h1-eth0")
        h1.cmd("ip route add 192.168.2.0/24 via 192.168.1.1")
        h1.cmd("ping 192.168.2.2 -c2")

        time.sleep(5)
        output = s1.cmdCLI("do show arp")
        output = output + "\n" + s1.cmdCLI("do show ipv6 neighbors")
        info(output + "\n\n")

        rows = output.split('\n')
        host1v4 = None
        mac_index = 1
        port_index = 2
        state_index = 3
        for row in rows:
            if '192.168.1.2' in row:
                host1v4 = row

        assert host1v4, "host 1 IPv4 not in neighbor table"
        max_index = self.column_count - 1
        info("\nVerifying MAC addresses and state\n")
        words = host1v4.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        mac = words[mac_index]
        assert mac == self.mac1, "Mac address of host1 incorrect"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"
        info("Host entry back to reachable state\n")

        info("########## End of unresolvable entry test ##########\n")

    def arp_manager_dp_hit(self):
        info("\n########## Test to verify arpmgr checks dp "
             "hit bit ##########\n")
        info("### If dp hit is not set, let kernel "
             "stale out entry ###\n")
        info("### If dp hit is empty or true keep entry "
             "reachable by probing ###\n")
        # configuring OpenSwitch, in the future it would be through
        # proper OpenSwitch commands
        s1 = self.net.switches[0]
        h1 = self.net.hosts[0]
        h2 = self.net.hosts[1]

        json_cfg_dp_hit = "ovsdb-client transact '[ \"OpenSwitch\",\
            {\"op\" : \"update\", \"table\" : \"Neighbor\",\"where\":\
            [[\"ip_address\",\"==\",\"2000::2\"]],\"row\":{\"status\":\
            [\"map\",[[\"dp_hit\",\"false\"]]]}}]'"

        s1.cmd(json_cfg_dp_hit)
        info("Configured dp hit to false for 2000::2. "
             "Entry should stale out within 45 seconds. Waiting.\n")

        max_index = self.column_count - 1
        timer = 50
        host1v4 = None
        host1v6 = None
        host2v4 = None
        host2v6 = None

        mac_index = 1
        port_index = 2
        state_index = 3
        while timer > 0:
            time.sleep(5)

            output = s1.cmdCLI("do show arp")
            output = output + "\n" + s1.cmdCLI("do show ipv6 neighbors")

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
            assert words.index(
                max(words)) == max_index, "Unknown number of columns"
            state = words[state_index]
            if state == 'stale':
                timer = 0
            else:
                timer = timer - 5

        info(output + "\n\n")
        info("\nVerifying states of host. 2000::2 should be stale. "
             "The rest of entries should be reachable\n")
        words = host1v4.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        words = host1v6.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        state = words[state_index]
        assert state == 'stale', "State incorrect, should be stale"

        words = host2v4.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        words = host2v6.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        info("States verified \n\n")
        info("Reset host 1 dp_hit to true\n")

        json_cfg_dp_hit = "ovsdb-client transact '[ \"OpenSwitch\",\
            {\"op\" : \"update\",\"table\" : \"Neighbor\",\"where\":\
            [[\"ip_address\",\"==\",\"2000::2\"]],\"row\":{\"status\":\
            [\"map\",[[\"dp_hit\",\"true\"]]]}}]'"

        s1.cmd(json_cfg_dp_hit)
        info("Configured dp hit to true for 2000::2. "
             "Entry should be reachable.\n")
        time.sleep(3);
        output = s1.cmdCLI("do show arp")
        output = output + "\n" + s1.cmdCLI("do show ipv6 neighbors")
        info(output + "\n\n")

        rows = output.split('\n')
        host1v6 = None

        for row in rows:
            if '2000::2' in row:
                host1v6 = row

        info("\nVerifying states of host. 2000::2 should be reachable.\n")
        max_index = self.column_count - 1
        words = host1v6.split()
        assert words.index(
            max(words)) == max_index, "Unknown number of columns"
        state = words[state_index]
        assert state == 'reachable', "State incorrect, should be reachable"

        info("2000::2 state is reachable\n")

        info("########## End of dp hit test ##########\n")

    def arp_manager_neighbor_delete(self):
        info("\n########## Test to verify arpmgr deletes row "
             "when kernel row gets deleted ##########\n")
        # configuring OpenSwitch, in the future it would be through
        # proper OpenSwitch commands
        s1 = self.net.switches[0]
        h1 = self.net.hosts[0]
        h2 = self.net.hosts[1]

        # Change IP address of interface 2. This will delete 192.168.2.2
        # neighbor
        info("Configuring ip 1.1.1.1 on switch 1 interface 2\n")
        s1.cmdCLI("interface 2")
        s1.cmdCLI("no ip address 192.168.2.1/24")
        s1.cmdCLI("exit")
        time.sleep(2)
        output = s1.cmdCLI("do show arp")
        output = output + "\n" + s1.cmdCLI("do show ipv6 neighbors")
        info(output + "\n\n")

        rows = output.split('\n')
        host2v4 = None

        for row in rows:
            if '192.168.2.2' in row:
                host2v4 = row

        assert host2v4 is None, \
            "Host 2 IP 192.168.2.2 still present in Neighbor table"

        info("Neighbor 192.168.2.2 deleted\n")

        # configure 192.168.2.1 address back on switch interface 2,
        # ping from host 2
        # host 2 entry should be back

        info("Configuring ip 192.168.2.1 on switch 1\n")
        s1.cmdCLI("interface 2")
        s1.cmdCLI("ip address 192.168.2.1/24")
        s1.cmdCLI("exit")

        h2.cmd("ping 192.168.2.1 -c2")

        time.sleep(3)
        output = s1.cmdCLI("do show arp")
        output = output + "\n" + s1.cmdCLI("do show ipv6 neighbors")
        info(output + "\n\n")

        rows = output.split('\n')
        host2v4 = None

        for row in rows:
            if '192.168.2.2' in row:
                host2v4 = row

        assert host2v4, "Host 2 IP 192.168.2.2 not present in Neighbor table"
        info("Host 2 entry 192.168.2.2 entry back in neighbor table\n")

        info("########## End of delete entry test ##########\n")


@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_arp_manager_functionality:
    # Create the Mininet topology based on mininet.

    def setup_class(cls):
        Test_arp_manager_functionality.test = arpManagerFunctionalityTests()

    # Configure and setup to run test cases
    def test_arp_manager_configure_and_setup(self):
        self.test.arp_manager_configure_and_setup()
    # Test for verifying arpmgr updates to db from kernel

    def test_arp_manager_ovsdb_update(self):
        self.test.arp_manager_ovsdb_update()
    # Test for verifying arpmgr reprobe and updating failed neighbor state

    def test_arp_manager_neighbor_fail(self):
        self.test.arp_manager_neighbor_fail()
    # Test for verifying arpmgr check dp hit to probe

    def test_arp_manager_dp_hit(self):
        self.test.arp_manager_dp_hit()
    # Test for verifying arpmgr verify neighbor delete

    def test_arp_manager_neighbor_delete(self):
        self.test.arp_manager_neighbor_delete()

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_arp_manager_functionality.test.net.stop()

    def __del__(self):
        del self.test
