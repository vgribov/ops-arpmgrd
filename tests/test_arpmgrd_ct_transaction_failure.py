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

from opsvsi.docker import *
from opsvsi.opsvsitest import *
from opsvsiutils.systemutil import *


class arpManagerTxnFailTests(OpsVsiTest):
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
        s1.cmdCLI("exit")

        # Configure interface 2 on switch s1
        s1.cmdCLI("interface 2")
        s1.cmdCLI("ip address 192.168.2.1/24")
        s1.cmdCLI("exit")

        # Configure interface 3 on switch s1
        s1.cmdCLI("interface 3")
        s1.cmdCLI("ip address 192.168.3.1/24")
        s1.cmdCLI("exit")

        # Configure interface 1
        s1.ovscmd("/usr/bin/ovs-vsctl set interface 1 user_config:admin=up")

        # Configure interface 2
        s1.ovscmd("/usr/bin/ovs-vsctl set interface 2 user_config:admin=up")

        # Configure interface 3
        s1.ovscmd("/usr/bin/ovs-vsctl set interface 3 user_config:admin=up")

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

        # Configure host 2
        info("Configuring host 2 with 192.168.2.2/24\n")
        h2.cmd("ip addr add 192.168.2.2/24 dev h2-eth0")
        h2.cmd("ip route add 192.168.1.0/24 via 192.168.2.1")
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

    def arp_manager_ovsdb_update(self):
        info("\n########## Test to verify arpmgr updates db with arp cache "
             "from kernel for directly connected hosts ##########\n")
        # configuring OpenSwitch, in the future it would be through
        # proper OpenSwitch commands
        s1 = self.net.switches[0]
        h1 = self.net.hosts[0]
        h2 = self.net.hosts[1]
        # Show Neighbors
        info("Show neighbors\n")
        # workaround to get latest update call show twice,
        # needs to be fixed in CLI
        output = s1.cmdCLI("do show arp")
        info(output + "\n\n")

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

        assert host1v4, "host 1 IPv4 not in neighbor table"
        assert host2v4, "host 2 IPv4 not in neighbor table"

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

        words = host2v4.split()
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

    def arp_manager_ovsdb_failure_check_new_updates(self):
        info("\n########## Test to verify arpmgr updates db with arp cache "
             "from kernel for hosts which cannot be resolved ##########\n")
        # configuring OpenSwitch, in the future it would be through
        # proper OpenSwitch commands
        s1 = self.net.switches[0]
        h1 = self.net.hosts[0]
        h2 = self.net.hosts[1]

        # Kill ovsdb to simulate a crash
        info("\nKilling ovsdb server\n")
        s1.cmd("ip netns exec swns killall ovsdb-server")
        # Kill l3 portd so it does not add new ip address
        # on restart which will clear neighbors
        s1.cmd("ip netns exec swns killall ops-portd")

        info("Adding 5 static arp entries before restarting ovsdb-server\n")
        # Add large number static arp entries
        # (not supported as functionality yet)
        # Just for CT purpose
        s1.cmd(
            "ip netns exec swns ip neigh add 192.168.1.101 \
            lladdr 00:bb:cc:dd:ee:ff dev 1")
        s1.cmd(
            "ip netns exec swns ip neigh add 192.168.1.102 \
            lladdr 00:bb:cc:dd:ee:ff dev 1")
        s1.cmd(
            "ip netns exec swns ip neigh add 192.168.1.103 \
            lladdr 00:bb:cc:dd:ee:ff dev 1")
        s1.cmd(
            "ip netns exec swns ip neigh add 192.168.1.104 \
            lladdr 00:bb:cc:dd:ee:ff dev 1")
        s1.cmd(
            "ip netns exec swns ip neigh add 192.168.1.105 \
            lladdr 00:bb:cc:dd:ee:ff dev 1")

        # Delete ip on interface 2 so 192.168.2.2 entry gets deleted
        s1.cmd("ip netns exec swns ip addr del 192.168.2.1/24 dev 2")

        # Delete host1 192.168.1.2 entry so its state goes to failed
        s1.cmd("ip netns exec swns ip neigh del 192.168.1.2 dev 1")

        # Restart arpmgrd
        info("Restarting ovsdb-server\n")
        s1.cmd("ip netns exec swns /usr/sbin/ovsdb-server \
               --remote=punix:/var/run/openvswitch/db.sock \
               --detach --no-chdir --pidfile -vSYSLOG:INFO \
               /var/run/openvswitch/ovsdb.db /var/local/openvswitch/config.db")

        time.sleep(8)

        output = s1.cmdCLI("do show arp")

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

        info("\n" + output + "\n\n")
        info("Verifying new static neighbors in ovsdb after ovsdb restart\n")
        assert static_entry1, "static entry 1 missing"
        assert static_entry2, "static entry 2 missing"
        assert static_entry3, "static entry 3 missing"
        assert static_entry4, "static entry 4 missing"
        assert static_entry5, "static entry 5 missing"

        info("New entries verified in ovsdb after ovsdb restart\n")

        assert 'failed' in host1v4, \
            "Host 1 192.168.1.2 should be in failed state"
        assert host2v4 is None, "Host 2 192.168.2.2 still in ovsdb"

        info("Verified modified/deleted entries after ovsdb restart\n")

@pytest.mark.skipif(True, reason="skipped test case due to random gate job failures.")
class Test_arp_manager_txn_fail:

    def setup_class(cls):
        # Create the Mininet topology based on mininet.
        Test_arp_manager_txn_fail.test = arpManagerTxnFailTests()

    # Configure and setup to run test cases
    def test_arp_manager_configure_and_setup(self):
        self.test.arp_manager_configure_and_setup()
    # Test for verifying arpmgr updates to db from kernel

    def test_arp_manager_ovsdb_update(self):
        self.test.arp_manager_ovsdb_update()

    # Test for verifying arpmgr updates to db from kernel
    def test_arp_manager_ovsdb_failure_check_new_updates(self):
        self.test.arp_manager_ovsdb_failure_check_new_updates()

    def teardown_class(cls):
        # Stop the Docker containers, and
        # mininet topology
        Test_arp_manager_txn_fail.test.net.stop()

    def __del__(self):
        del self.test
