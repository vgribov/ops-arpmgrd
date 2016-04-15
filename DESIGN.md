High level design of ops-arpmgrd
================================

The **ops-arpmgrd** process receives neighbor notifications from the kernel and manages rows in the Neighbor database table.

Responsibilities
-----------------
The **ops-arpmgrd** process is responsible for monitoring neighbor entries in the kernel (IPv4 and IPv6) and updating the Neighbor table with the neighbor entries. This daemon also refreshes kernel entries for neighbor entries with active traffic in the datapath.

Design choices
-----------------
The **ops-arpmgrd** process was added to the OpenSwitch architecture in order to leverage the Linux kernel for neighbor management and learning. The role of **ops-arpmgrd** is to keep the Neighbor table in sync with Linux neighbor entries. Linux then `learns` new neighbors in the slow path. Once learned, subsequent traffic flows in the datapath, not through the kernel, thereby making **ops-arpmgrd** responsible for keeping these entries up to date. Linux manages inactive neighbors using an `ageout` which avoids using a different approach that would be platform-specific and platform-dependent.

Relationships to external OpenSwitch entities
---------------------------------------------
```ditaa
    +--------+
    |  OVSDB +-----------+
    +---^----+           |
        |                |
        |                |
    +---v-------+  +-----v-----+
    |ops-arpmgrd|  |ops-switchd|
    +---^-------+  +-----+-----+
        |                |
        |                |
    +---v--------+  +----v------+
    |Linux Kernel|  |   ASIC    |
    +------------+  +-----+-----+

```

The **ops-arpmgrd** registers for notifications from the kernel for neighbor updates using Netlink sockets. The daemon receives messages for the new neighbor, the modified neighbor (state change), and the deleted neighbor. On receiving a notification, **ops-arpmgrd** updates its local cache and then updates the Neighbor table in OVSDB. The **ops-arpmgrd** also monitors the other_config:dp_hit column of Neighbor table which is updated by **ops-vswitchd**. This key is updated to `true` if there is traffic for the neighbor in datapath. If this value is `true`, the **ops-arpmgrd** triggers kernel to probe for the neighbor when the entry goes to a`stale` state.

The **ops-vswitchd** registers for the Neighbor table updates and programs the ASIC with new neighbors and deletes ASIC entries for deleted neighbors or neighbors in a `failed` state.

OVSDB-Schema
------------
### Neighbor table
* **vrf**: The VRF on which this neighbor was learned. Currently OpenSwitch supports only one VRF.
* **ip_address**: IPv4 or IPv6 address of the neighbor.
* **address_family**: IPv4 or IPv6.
* **mac**: MAC address of the neigbor if neighbor is successfully resolved. If the neighbor resolution fails, this column is empty.
* **port**: The port on which the neighbor was resolved.
* **state**: Neighbor states can be one of the following: reachable, stale, failed. Static/Permanent entries are not yet supported.
* **status**: The **ops-arpmgrd** process monitors the `status:dp_hit` field in the Subsystem table to determine active traffic in datapath for neighbor. If traffic is active, **ops-arpmgrd** sets the kernel state of the neighbor to `delay`, which schedules neighbor probes to refresh the kernel entry.

Code design
-----------
* **initialization**: Subscribe to database tables and columns, and general initialization.
* main loop
  * **reconfigure**: The process changes to the `status:dp_hit` column for any neighbor. If `status:dp_hit` got modified to `true`, set state of neighbor entry in the kernel to `delay` so that the kernel schedules an neighbor probe.
  * **run**: Receives a netlink message on netlink socket registered with RTMGRP_NEIGH group for neighbor updates from kernel. The **ops-arpmgrd** process handles receiving of the following Netlink message types: RTM_NEWNEIGH, RTM_DELNEIGH. Neighbor add, neighbor state modification and neighbor deletes are first updated in the local cache `all_neighbors` and then updated to the database.
  * **handle restartability and transaction failures**: To handle restartability and transaction failures **ops-arpmgrd** uses same approach. A new transaction is created in either case, with a complete resync of kernel with OVSDB in this new transaction. The resync is optimized in the following way:
     - Populate local cache `all_neighbors` with kernel entries.
     - Create a hash of OVSDB entries.
     - Loop over list of local_cache, and if entry is not present in OVSDB entry hash, create new row, else modify existing row.
     - Loop over OVSDB entries and lookup local_cache. If entry is not found, delete the neighbor from OVSDB.

References
----------
* [Linux kernel arp cache](http://linux-ip.net/html/ether-arp.html)
* [Neighboring subsystem](http://www.linuxfoundation.org/collaborate/workgroups/networking/neighboring_subsystem)
* [rtnetlink](http://man7.org/linux/man-pages/man7/rtnetlink.7.html)
